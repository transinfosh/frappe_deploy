"""Deployment updates the Runtime endpoint without rewriting model configuration."""
import contextlib
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'multi-node/ansible/roles/tai_control_config/templates/configure_settings.py.j2'


class ControlSettingsUpgradeTests(unittest.TestCase):
    def render(self):
        env = Environment(undefined=StrictUndefined)
        env.filters['to_json'] = json.dumps
        return env.from_string(TEMPLATE.read_text()).render(
            control_site_name='control.example.test', runtime_public_hostname='runtime.example.test',
            embedding_provider_key='must-not-apply', embedding_model='must-not-apply',
            embedding_dimensions=1024, embedding_timeout_seconds=15, embedding_backfill_batch_size=64,
        )

    def test_upgrade_preserves_models_and_is_idempotent(self):
        settings = {'agent_runtime_url': 'https://old.example.test', 'chat_model_key': 'existing-chat',
                    'embedding_enabled': 0, 'embedding_model_key': 'existing-embedding',
                    'embedding_dimensions': 3072, 'active_model_configuration_revision': 'saved-revision'}
        original = dict(settings)
        allowed = {'agent_runtime_url'}
        def read(doctype, field):
            self.assertEqual(doctype, 'TAI Control Settings')
            self.assertIn(field, allowed)
            return settings[field]
        def write(doctype, field, value):
            read(doctype, field)
            settings[field] = value
        frappe = types.ModuleType('frappe')
        frappe.db = types.SimpleNamespace(get_single_value=read, set_single_value=write, commit=Mock())
        frappe.clear_cache = Mock()
        for changed in (True, False):
            stream = io.StringIO()
            with patch.dict(sys.modules, {'frappe': frappe}), contextlib.redirect_stdout(stream):
                exec(compile(self.render(), str(TEMPLATE), 'exec'), {})
            self.assertEqual(json.loads(stream.getvalue().split('=', 1)[1]), {
                'changed': changed, 'agent_runtime_url': 'https://runtime.example.test'})
        self.assertEqual(settings, {**original, 'agent_runtime_url': 'https://runtime.example.test'})
        frappe.db.commit.assert_called_once()
        frappe.clear_cache.assert_called_once_with(doctype='TAI Control Settings')

    def test_only_runtime_endpoint_is_required_for_rendering(self):
        script = Environment(undefined=StrictUndefined).from_string(TEMPLATE.read_text()).render(
            runtime_public_hostname='runtime.example.test')
        compile(script, str(TEMPLATE), 'exec')


if __name__ == '__main__':
    unittest.main()
