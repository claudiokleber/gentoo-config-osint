import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from gentoosint.cli import main
from gentoosint.inventory import collect, parse_os_release
from gentoosint.diagnostics import diagnose
from gentoosint.planner import make_plan, resolve


class GentooSintTests(unittest.TestCase):
    def inventory(self, distro="gentoo", init="systemd"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in {"etc/os-release": f'ID="{distro}"\nSECRET=do-not-export',
                               "proc/meminfo": "MemTotal: 2000000 kB\nMemAvailable: 100000 kB\nSwapTotal: 0 kB\n",
                               "proc/1/comm": init}.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
            return collect(root, "Linux", "aarch64", which=lambda name: "/usr/bin/"+name)

    def test_linux_inventory(self):
        inv = self.inventory()
        self.assertTrue(inv["is_gentoo"])
        self.assertEqual(inv["architecture"], "aarch64")
        self.assertEqual(inv["init"], "systemd")
        self.assertEqual(inv["memory_total_kib"], 2000000)
        self.assertNotIn("SECRET", json.dumps(inv))

    def test_openrc_and_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); mark=root/'run/openrc/softlevel'
            mark.parent.mkdir(parents=True); mark.write_text('default')
            inv=collect(root, 'Linux', which=lambda _:None)
            self.assertEqual(inv['init'],'openrc')
            self.assertIsNone(inv['memory_total_kib'])
            self.assertFalse(inv['is_gentoo'])

    def test_release_is_data_not_code(self):
        self.assertEqual(parse_os_release('ID=gentoo\nTOKEN=$(bad)\n'), {"ID":"gentoo"})

    def test_other_distribution_not_eligible(self):
        plan=make_plan(self.inventory('ubuntu'), ['tor'])
        self.assertFalse(plan['target_eligible'])
        with self.assertRaises(ValueError): resolve(plan)

    def test_unknown_module_and_shell_injection_rejected(self):
        for name in ['tor;reboot', '--help', 'unknown']:
            with self.assertRaises(ValueError): make_plan(self.inventory(), [name])

    def test_plan_deduplicates(self):
        plan=make_plan(self.inventory(), ['tor','tor','osint'])
        self.assertEqual(plan['pretend_argv'].count('net-vpn/tor'),1)
        self.assertFalse(plan['changes_applied'])

    def test_resolver_read_only_arguments(self):
        calls=[]
        def runner(argv, **kwargs):
            calls.append((argv,kwargs)); return SimpleNamespace(returncode=0)
        inv = self.inventory()
        with patch('gentoosint.planner.collect', return_value=inv), patch('gentoosint.planner.trusted_emerge', return_value='/usr/bin/emerge'):
            result=resolve(make_plan(inv, ['tor']), runner)
        self.assertEqual(result['resolution'],'passed')
        self.assertIn('--pretend',calls[0][0])
        self.assertFalse(calls[0][1]['shell'])
        self.assertNotIn('--autounmask-write',calls[0][0])

    def test_resolver_failure_timeout_missing(self):
        inv=self.inventory()
        plan=make_plan(inv,['tor'])
        def timeout(*a,**k): raise subprocess.TimeoutExpired('emerge',120)
        def missing(*a,**k): raise FileNotFoundError()
        with patch('gentoosint.planner.collect', return_value=inv), patch('gentoosint.planner.trusted_emerge', return_value='/usr/bin/emerge'):
            self.assertEqual(resolve(plan, lambda *a,**k:SimpleNamespace(returncode=1))['resolution'],'failed')
            self.assertEqual(resolve(plan,timeout)['resolution'],'timeout')
            self.assertEqual(resolve(plan,missing)['resolution'],'unavailable')

    def test_measured_findings(self):
        codes={f['code'] for f in diagnose(self.inventory())}
        self.assertIn('memory-pressure',codes)
        self.assertIn('limited-memory',codes)

    def test_no_subprocess_default_commands(self):
        with patch('subprocess.Popen',side_effect=AssertionError('Must not execute')), contextlib.redirect_stdout(io.StringIO()):
            for args in [['doctor'],['optimize'],['catalog'],['audit'],['verify'],['plan','--modules','tor']]:
                self.assertEqual(main(args),0)

    def test_output_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'report.json'; path.write_text('keep')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['doctor','--output',str(path)]),2)
            self.assertEqual(path.read_text(),'keep')

    def test_json_cli(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(['doctor','--format','json']),0)
        result=json.loads(output.getvalue())
        self.assertFalse(result['changes_applied'])
        self.assertNotIn('hostname',result['inventory'])


if __name__ == '__main__': unittest.main()
