import contextlib
import copy
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from gentoosint.checks import audit, verify
from gentoosint.cli import main, markdown
from gentoosint.inventory import read_text, memory_kib, windows_memory
from gentoosint.planner import make_plan, resolve
from gentoosint.process import run_bounded
from gentoosint.security import safe_text, write_report, trusted_emerge


def fixture():
    return {'is_gentoo': True, 'emerge_available': True, 'system': 'Linux',
            'architecture': 'x86_64', 'distribution': 'gentoo', 'init': 'openrc',
            'profile': 'default/linux/amd64/23.0',
            'executables': {'tor': True, 'gnupg': False, 'dns': False, 'exiftool': False}}


class SecurityTests(unittest.TestCase):
    def test_modified_command_rejected(self):
        inv=fixture()
        for key, value in [('pretend_argv', ['/bin/sh','-c','id']),
                           ('target_eligible', True), ('modules', ['tor;id']),
                           ('schema_version', 999), ('mode', 'apply')]:
            plan=make_plan(inv,['tor'])
            if key=='target_eligible':
                plan['target']['architecture']='arm64'
            else: plan[key]=value
            with patch('gentoosint.planner.collect',return_value=inv), patch('gentoosint.planner.trusted_emerge') as executable:
                with self.assertRaises(ValueError): resolve(plan)
                executable.assert_not_called()

    def test_fresh_target_required(self):
        plan=make_plan(fixture(),['tor'])
        current=dict(fixture(),is_gentoo=False,distribution='ubuntu')
        with patch('gentoosint.planner.collect',return_value=current):
            with self.assertRaises(ValueError): resolve(plan)

    def test_no_environment_injection(self):
        inv=fixture(); captured={}
        def runner(argv,**kwargs):
            captured.update(kwargs); captured['argv']=argv
            return SimpleNamespace(returncode=0)
        with patch.dict(os.environ, {'PYTHONPATH':'/evil','LD_PRELOAD':'/evil','BASH_ENV':'/evil'}), patch('gentoosint.planner.collect',return_value=inv), patch('gentoosint.planner.trusted_emerge',return_value='/usr/bin/emerge'):
            resolve(make_plan(inv,['tor']),runner)
        self.assertEqual(captured['argv'][0],'/usr/bin/emerge')
        self.assertNotIn('PYTHONPATH',captured['env'])
        self.assertNotIn('LD_PRELOAD',captured['env'])
        self.assertNotIn('BASH_ENV',captured['env'])
        self.assertEqual(captured['cwd'],'/')
        self.assertEqual(captured['stdin'],subprocess.DEVNULL)

    def test_timeout_bounds(self):
        for value in [0,-1,301,True,'10']:
            with self.assertRaises(ValueError): resolve({},timeout=value)

    def test_trusted_binary_rejects_writable_mode_and_non_root(self):
        for owner,mode in [(0,stat.S_IFREG|0o777),(1000,stat.S_IFREG|0o755)]:
            with patch('gentoosint.security.os.name','posix'), patch('gentoosint.security.Path') as path:
                executable=MagicMock(); executable.parents=[]
                executable.stat.return_value=SimpleNamespace(st_uid=owner,st_mode=mode)
                path.return_value.resolve.return_value=executable
                with self.assertRaises(ValueError): trusted_emerge()

    def test_timeout_kills_process_group(self):
        child=MagicMock(); child.pid=12345
        child.wait.side_effect=[subprocess.TimeoutExpired('test',1), None]
        with patch('gentoosint.process.subprocess.Popen') as popen, patch('gentoosint.process.os.name','posix'), patch('gentoosint.process.os.killpg',create=True) as killpg, patch('gentoosint.process.signal.SIGKILL',9,create=True):
            popen.return_value.__enter__.return_value=child
            with self.assertRaises(subprocess.TimeoutExpired): run_bounded(['test'],timeout=1)
            killpg.assert_called_once()
            self.assertEqual(killpg.call_args.args[0],12345)

    def test_interrupt_kills_process_group(self):
        child=MagicMock(); child.pid=12345
        child.wait.side_effect=[KeyboardInterrupt(),None]
        with patch('gentoosint.process.subprocess.Popen') as popen, patch('gentoosint.process.os.name','posix'), patch('gentoosint.process.os.killpg',create=True) as killpg, patch('gentoosint.process.signal.SIGKILL',9,create=True):
            popen.return_value.__enter__.return_value=child
            with self.assertRaises(KeyboardInterrupt): run_bounded(['test'])
            killpg.assert_called_once()

    def test_reports_new_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'report.json'
            write_report(path,'{"status":"ok"}')
            with self.assertRaises(FileExistsError): write_report(path,'bad')
            self.assertEqual(json.loads(path.read_text())['status'],'ok')
            if os.name=='posix': self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)

    def test_report_bad_names(self):
        for value in ['../report.md','NUL.json','file.json:stream','file.py']:
            with self.assertRaises(ValueError): write_report(Path(value),'bad')

    @unittest.skipUnless(os.name=='posix','POSIX symlink/FIFO integration requires Linux')
    def test_symlink_and_fifo_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); destination=root/'existing.json'; destination.write_text('keep')
            link=root/'link.json'; link.symlink_to(destination)
            with self.assertRaises(OSError): write_report(link,'bad')
            directory=root/'redirect'; directory.symlink_to(root,target_is_directory=True)
            with self.assertRaises(OSError): write_report(directory/'new.json','bad')
            fifo=root/'pipe'; os.mkfifo(fifo)
            self.assertIsNone(read_text(fifo))

    def test_reparse_parent_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch('gentoosint.security.os.name','nt'), patch.object(Path,'lstat',return_value=SimpleNamespace(st_file_attributes=0x400)):
                with self.assertRaises(ValueError): write_report(Path(tmp)/'new.md','bad')

    def test_bounded_reads_and_numbers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'large';path.write_text('x'*300000)
            self.assertEqual(len(read_text(path)),262144)
        self.assertIsNone(memory_kib('MemTotal: '+'9'*5000+' kB','MemTotal'))

    def test_controls_removed_and_fences_balanced(self):
        self.assertNotIn('\x1b',safe_text('\x1b[31mhello'))
        self.assertNotIn('\u202e',safe_text('a\u202eb'))
        report=markdown({'value':'```\nmalicious'})
        self.assertIn('````json',report)
        self.assertTrue(report.endswith('````\n'))

    def test_verify_does_not_confuse_similar_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); category=root/'var/db/pkg/net-vpn';category.mkdir(parents=True)
            (category/'tor-browser-1.0').mkdir()
            result=verify(fixture(),['tor'],root)['tools'][0]
            self.assertEqual(result['package_status'],'not-recorded')
            (category/'tor-0.4.9.13').mkdir()
            result=verify(fixture(),['tor'],root)['tools'][0]
            self.assertEqual(result['versions'],['0.4.9.13'])
            self.assertEqual(result['functional_status'],'not-tested')

    def test_missing_database_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=verify(fixture(),['tor'],Path(tmp))['tools'][0]
            self.assertEqual(result['package_status'],'unknown')

    def test_audit_reports_unsafe_path_without_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=audit(fixture(),Path(tmp),{'PATH':'.'+os.pathsep+'/usr/bin','TOKEN':'secret'})
        self.assertEqual(result['checks'][0]['status'],'warning')
        self.assertNotIn('secret',json.dumps(result))

    def test_cli_abbreviations_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit): main(['plan','--mod','tor'])

    def test_windows_memory_call(self):
        if sys.platform != 'win32': self.skipTest('Native Windows API')
        total,available=windows_memory()
        self.assertGreater(total,0)
        self.assertLessEqual(available,total)

    def test_verify_permission_denied_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'var/db/pkg/net-vpn').mkdir(parents=True)
            with patch('gentoosint.checks.os.scandir',side_effect=PermissionError()):
                self.assertEqual(verify(fixture(),['tor'],root)['tools'][0]['package_status'],'unknown')

    def test_audit_permissions_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(Path,'lstat',return_value=SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o666)):
                result=audit(fixture(),Path(tmp),{'PATH':'/usr/bin'})
            self.assertTrue(all(c['status']=='warning' for c in result['checks'][1:]))

    def test_overlong_and_wrong_type_modules(self):
        for modules in [None,'tor',[{}],['tor']*17,['a'*33]]:
            with self.assertRaises(ValueError): make_plan(fixture(),modules)

    def test_real_child_exit_code(self):
        result=run_bounded([sys.executable,'-I','-c','raise SystemExit(7)'],timeout=10,
                           stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.assertEqual(result.returncode,7)


if __name__=='__main__': unittest.main()
