"""Offline regression tests. All privileged commands are replaced with fixtures."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

SOURCE = Path(os.environ.get('KILLSWITCH_TEST_SOURCE', str(Path(__file__).resolve().parents[1] / 'claude-killswitch')))


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='killswitch-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ, FIXTURE=str(self.root))
        source = SOURCE.read_text().split('\ncommand=${1:-}', 1)[0]
        for real, fake in [('/sbin/pfctl', 'fake_pfctl'),
                           ('/bin/launchctl', 'fake_launchctl'),
                           ('/usr/bin/install', 'fake_install'),
                           ('/usr/bin/plutil', 'fake_plutil'),
                           ('/bin/sleep', 'fake_sleep')]:
            source = source.replace(real, fake)
        mock = r'''
trap - EXIT
ANCHOR_FILE="$FIXTURE/anchor"
PF_CONF="$FIXTURE/pf.conf"
TEMP_DIR="$FIXTURE"
DAEMON_PLIST="$FIXTURE/daemon.plist"
require_root() { :; }
physical_interfaces() { printf 'en0\nbridge0\n'; }
proxy_health() { printf 'fixture\n'; }
route_interface() { printf 'utun0\n'; }
fake_sleep() { :; }
fake_install() { :; }
fake_plutil() { :; }
fake_pfctl() {
  case "$*" in
    '-s info') printf 'Status: Enabled\n' ;;
    '-sr') cat "$FIXTURE/root.rules" ;;
    *'-t anthropic_ipv4 -T show') cat "$FIXTURE/v4" ;;
    *'-t public_ipv6 -T show') cat "$FIXTURE/v6" ;;
    *'-sr') cat "$FIXTURE/runtime.rules" ;;
    *) printf '%s\n' "$*" >> "$FIXTURE/pf.calls" ;;
  esac
}
fake_launchctl() {
  printf '%s\n' "$*" >> "$FIXTURE/launch.calls"
  case "$1" in
    print) [ -f "$FIXTURE/registered" ] || return 1
           if [ -f "$FIXTURE/stopped" ]; then
             printf 'state = waiting\n'
           else
             printf 'state = running\n'
           fi ;;
    bootstrap) if [ -f "$FIXTURE/fail-once" ]; then
                 rm "$FIXTURE/fail-once"; return 5
               fi
               touch "$FIXTURE/registered" ;;
    kickstart) rm -f "$FIXTURE/stopped" ;;
    bootout) return 99 ;;
  esac
}
'''
        self.library = self.root / 'library.sh'
        self.library.write_text(source + mock)
        self.shell(r'''write_anchor "$ANCHOR_FILE" "$(physical_interfaces)"
: > "$PF_CONF"
write_pf_candidate "$FIXTURE/candidate" "$FIXTURE/stripped"
mv "$FIXTURE/candidate" "$PF_CONF"
printf 'anchor "%s" all\n' "$ANCHOR_NAME" > "$FIXTURE/root.rules"
printf '%s\n' "$ANTHROPIC_IPV4" | normalize_networks > "$FIXTURE/v4"
printf '%s\n' "$PUBLIC_IPV6" | normalize_networks > "$FIXTURE/v6"
grep '^block ' "$ANCHOR_FILE" > "$FIXTURE/runtime.rules"
touch "$FIXTURE/registered"
''')

    def shell(self, body, expected=0):
        p = subprocess.run(['/bin/bash', '-c', '. ' + shlex.quote(str(self.library)) + '\n' + body],
                           env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(p.returncode, expected, 'unexpected health result: ' + p.stderr)
        return p.stdout

    def test_healthy_configuration_and_kernel(self):
        self.shell('configuration_complete; runtime_rules_complete; status_rules')

    def test_missing_new_range_is_unhealthy(self):
        p = self.root / 'v4'
        p.write_text(p.read_text().splitlines()[0] + '\n')
        self.shell('runtime_rules_complete', expected=1)
        out = self.shell('status_rules', expected=1)
        self.assertIn('不完整', out)

    def test_wrong_range_with_same_count_is_unhealthy(self):
        self.shell('printf "%s\n" "192.0.2.0/24" "198.51.100.0/24" > "$FIXTURE/v4"; runtime_rules_complete', expected=1)

    def test_ipv6_table_gap_is_unhealthy(self):
        (self.root / 'v6').write_text('2000::/3\n')
        self.shell('runtime_rules_complete', expected=1)

    def test_rule_count_does_not_make_pass_rules_safe(self):
        p = self.root / 'runtime.rules'
        p.write_text(p.read_text().replace('block drop out quick', 'pass out quick'))
        self.shell('runtime_rules_complete', expected=9)

    def test_new_interface_gap_is_unhealthy(self):
        self.shell('physical_interfaces() { printf "en0\nen9\n"; }; runtime_rules_complete', expected=9)

    def test_detached_anchor_is_unhealthy(self):
        (self.root / 'root.rules').write_text('')
        self.shell('runtime_rules_complete', expected=1)

    def test_stale_disk_table_is_unhealthy(self):
        p = self.root / 'anchor'
        p.write_text(re.sub(r'^table <anthropic_ipv4>.*$', 'table <anthropic_ipv4> const { 192.0.2.0/24 }', p.read_text(), flags=re.M))
        self.shell('configuration_complete', expected=1)

    def test_registered_but_stopped_is_not_running(self):
        (self.root / 'stopped').touch()
        self.shell('daemon_active', expected=1)
        self.shell('status_rules', expected=1)

    def test_upgrade_keeps_registration_and_restarts_watcher(self):
        self.shell('install_daemon; daemon_active')
        calls = (self.root / 'launch.calls').read_text()
        self.assertIn('kickstart -k ', calls)
        self.assertNotIn('bootout', calls)
        self.assertNotIn('bootstrap', calls)

    def test_first_install_retries_transient_bootstrap_failure(self):
        (self.root / 'registered').unlink()
        (self.root / 'fail-once').touch()
        self.shell('install_daemon; daemon_active')
        calls = (self.root / 'launch.calls').read_text()
        self.assertEqual(calls.count('bootstrap system '), 2)
        self.assertNotIn('bootout', calls)

    def test_runtime_repair_reloads_only_referenced_anchor(self):
        self.shell('ensure_pf_runtime')
        calls = (self.root / 'pf.calls').read_text().splitlines()
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith('-a '))

    def test_runtime_repair_restores_missing_root_reference(self):
        (self.root / 'root.rules').write_text('')
        self.shell('ensure_pf_runtime')
        calls = (self.root / 'pf.calls').read_text().splitlines()
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith('-f '))


if __name__ == '__main__':
    unittest.main(verbosity=2)
