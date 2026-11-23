"""Regression checks for manifest decoding and source-report preservation."""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from src import scanner
from src.dependency_audit import audit_dependencies


@pytest.mark.parametrize('encoding', ['utf-8', 'utf-8-sig', 'utf-16', 'utf-16-be'])
def test_manifest_normalized_and_original_preserved(tmp_path, monkeypatch, encoding):
    text = '# café\nexample==1.0\n'
    raw = text.encode(encoding)
    if encoding == 'utf-16-be':
        raw = b'\xfe\xff' + raw
    manifest = tmp_path / 'requirements.txt'
    manifest.write_bytes(raw)
    seen = []
    def run(command, **kwargs):
        normalized = Path(command[command.index('-r') + 1])
        seen.append(normalized)
        assert normalized != manifest
        assert normalized.read_bytes() == b'example==1.0\n'
        assert '--no-deps' in command and '--disable-pip' in command
        return SimpleNamespace(returncode=0, stdout='{"dependencies": []}')
    monkeypatch.setattr('src.dependency_audit.subprocess.run', run)
    report = audit_dependencies(tmp_path)
    assert report['status'] == 'completed'
    assert report['input'] == str(manifest)
    assert manifest.read_bytes() == raw
    assert not seen[0].exists()


@pytest.mark.parametrize('raw', [b'\xffbad', b'\xff\xfex', 'example==1.0'.encode('utf-32')])
def test_bad_encoding_is_reported(tmp_path, monkeypatch, raw):
    (tmp_path / 'requirements.txt').write_bytes(raw)
    monkeypatch.setattr('src.dependency_audit.subprocess.run', lambda *a, **k: pytest.fail('must not run'))
    report = audit_dependencies(tmp_path)
    assert report['status'] == 'failed'
    assert report['reason'] == 'manifest_decoding_error'


def test_normalized_manifest_removed_after_timeout(tmp_path, monkeypatch):
    (tmp_path / 'requirements.txt').write_text('example==1.0')
    seen = []
    def run(command, **kwargs):
        seen.append(Path(command[command.index('-r') + 1]))
        raise subprocess.TimeoutExpired(command, 1)
    monkeypatch.setattr('src.dependency_audit.subprocess.run', run)
    assert audit_dependencies(tmp_path)['reason'] == 'audit_timeout'
    assert not seen[0].exists()


@pytest.mark.parametrize('crash', [False, True])
def test_source_saved_before_dependency_audit(tmp_path, monkeypatch, crash):
    target = tmp_path / 'example.py'
    target.write_text('eval(input())')
    finding = {'scanner':'bandit','rule_id':'B307','file':str(target),'line':1,'severity':'HIGH','message':'unsafe eval'}
    results = {'bandit':{'results':[{'test_id':'B307'}]},'semgrep':{'results':[]}}
    coverage = {'status':'completed','files':[{'scanners':{'bandit':'completed','semgrep':'completed'}}]}
    monkeypatch.setattr(scanner, 'ROOT', tmp_path)
    monkeypatch.setattr(scanner, 'scan_target', lambda *a: (results, [finding], coverage))
    monkeypatch.setattr('src.reporting.scanner_metadata', lambda *a: {'bandit':{},'semgrep':{}})
    monkeypatch.setattr(sys, 'argv', ['scanner', str(target), '--no-llm'])
    def audit(*args):
        folder, = (tmp_path / 'reports').iterdir()
        for name in ('bandit','semgrep','findings','report','ai_reviews'):
            assert (folder / (name + '.json')).is_file()
        saved = json.loads((folder / 'report.json').read_text())
        assert saved['findings'][0]['rule_id'] == 'B307'
        assert saved['dependencies']['status'] == 'pending'
        if crash:
            raise RuntimeError('unexpected audit failure')
        return {'status':'failed','reason':'manifest_decoding_error','packages':[],'findings':[]}
    monkeypatch.setattr('src.dependency_audit.audit_dependencies', audit)
    scanner.main()
    saved = json.loads(next((tmp_path / 'reports').glob('*/report.json')).read_text())
    assert saved['findings'][0]['rule_id'] == 'B307'
    assert saved['dependencies']['status'] == 'failed'
