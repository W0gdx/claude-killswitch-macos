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
                           ('/bin/sleep', 'fake_sleep'),
                           ('/sbin/route', 'fake_route'),
                           ('/usr/bin/nc', 'fake_nc'),
                           ('/usr/bin/stat', 'fake_stat'),
                           ('/bin/ls', 'fake_ls')]:
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
fake_stat() { printf '0 755\n'; }
fake_ls() { :; }
fake_nc() { return 1; }
fake_route() {
  printf '%s\n' "$*" >> "$FIXTURE/route.calls"
  case "$*" in
    *'get -host'*)
      if [ -f "$FIXTURE/query-failed" ]; then return 1; fi
      if [ -f "$FIXTURE/route-present" ]; then
        printf 'destination: %s\ngateway: %s\ninterface: %s\nflags: <UP,GATEWAY,HOST,STATIC,IFSCOPE>\n' "$VERIFY_ADDRESS" "${MOCK_GATEWAY:-$VERIFY_GATEWAY}" "${MOCK_INTERFACE:-$VERIFY_INTERFACE}"
      else
        printf 'destination: default\ninterface: en0\n'
      fi ;;
    *'delete -host'*)
      if [ -f "$FIXTURE/delete-failed" ]; then return 1; fi
      rm -f "$FIXTURE/route-present" ;;
  esac
}
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
    *'-vvsr') cat "$FIXTURE/verbose.rules" ;;
    *'-sr') cat "$FIXTURE/runtime.rules" ;;
    *) if [ -f "$FIXTURE/pf-load-failed" ]; then return 1; fi
       printf '%s\n' "$*" >> "$FIXTURE/pf.calls" ;;
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
    bootout) if [ -f "$FIXTURE/bootout-failed" ]; then return 5; fi
             rm -f "$FIXTURE/registered" ;;
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

    def test_root_owned_safe_metadata(self):
        self.shell('path_metadata_safe 0 755 ""; path_metadata_safe 0 600 ""')

    def test_non_root_owner_refused(self):
        self.shell('path_metadata_safe 501 755 ""', expected=1)

    def test_group_writable_refused(self):
        self.shell('path_metadata_safe 0 775 ""', expected=1)

    def test_world_writable_refused(self):
        self.shell('path_metadata_safe 0 777 ""', expected=1)

    def test_write_granting_acl_refused(self):
        self.shell('path_metadata_safe 0 755 "0: group:staff allow add_file,writeattr"', expected=1)

    def test_deny_acl_allowed(self):
        self.shell('path_metadata_safe 0 755 "0: group:everyone deny delete"')

    def test_symlink_install_path_refused(self):
        (self.root / 'target').touch()
        (self.root / 'link').symlink_to(self.root / 'target')
        self.shell('secure_path "$FIXTURE/link"', expected=1)

    def test_existing_safe_path_allowed(self):
        (self.root / 'target').touch()
        self.shell('secure_path "$FIXTURE/target"')

    def setup_route(self):
        (self.root / 'route-present').touch()
        return 'VERIFY_ROUTE_ADDED=1; VERIFY_INTERFACE=en0; VERIFY_ADDRESS=192.0.2.1; VERIFY_GATEWAY=192.0.2.254; '

    def test_cleanup_deletes_scoped_route_and_reads_back(self):
        self.shell(self.setup_route() + 'remove_test_route; [ "$VERIFY_ROUTE_ADDED" -eq 0 ]')
        calls = (self.root / 'route.calls').read_text().splitlines()
        self.assertEqual(len(calls), 3)
        self.assertIn('delete -host -ifscope en0 ', calls[1])

    def test_route_changed_to_other_gateway_is_not_deleted(self):
        self.shell(self.setup_route() + 'MOCK_GATEWAY=198.51.100.1; remove_test_route', expected=1)
        self.assertNotIn('delete', (self.root / 'route.calls').read_text())

    def test_route_changed_to_other_interface_is_not_deleted(self):
        self.shell(self.setup_route() + 'MOCK_INTERFACE=en9; remove_test_route', expected=1)
        self.assertNotIn('delete', (self.root / 'route.calls').read_text())

    def test_failed_route_deletion_is_failure(self):
        (self.root / 'delete-failed').touch()
        self.shell(self.setup_route() + 'remove_test_route', expected=1)

    def test_failed_route_query_is_not_assumed_clean(self):
        (self.root / 'query-failed').touch()
        self.shell(self.setup_route() + 'remove_test_route', expected=1)

    def test_already_absent_route_is_clean(self):
        body = self.setup_route()
        (self.root / 'route-present').unlink()
        self.shell(body + 'remove_test_route; [ "$VERIFY_ROUTE_ADDED" -eq 0 ]')
        self.assertNotIn('delete', (self.root / 'route.calls').read_text())

    def test_no_owned_route_means_no_route_mutation(self):
        self.shell('remove_test_route')
        self.assertFalse((self.root / 'route.calls').exists())

    def test_cleanup_failure_overrides_success_exit(self):
        (self.root / 'delete-failed').touch()
        self.shell(self.setup_route() + 'finish 0', expected=1)

    def test_cleanup_preserves_unverified_exit(self):
        self.shell('finish 2', expected=2)

    def test_failed_rule_restore_is_failure(self):
        (self.root / 'pf-load-failed').touch()
        self.shell('VERIFY_RULES_CHANGED=1; cleanup', expected=1)

    def test_successful_rule_restore_is_read_back(self):
        self.shell('VERIFY_RULES_CHANGED=1; cleanup; [ "$VERIFY_RULES_CHANGED" -eq 0 ]')

    def test_uninstall_does_not_remove_files_if_daemon_stop_fails(self):
        (self.root / 'bootout-failed').touch()
        self.shell('assert_secure_installation_paths() { :; }; uninstall_rules', expected=1)
        self.assertTrue((self.root / 'anchor').exists())
        self.assertTrue((self.root / 'pf.conf').exists())
        self.assertNotIn('-f ', (self.root / 'pf.calls').read_text() if (self.root / 'pf.calls').exists() else '')

    def test_verify_counter_reads_only_the_labelled_rule(self):
        self.shell(r"""printf '@0 block drop out quick label "other"\n [ Packets: 99 Bytes: 0 ]\n@1 block drop out quick label "%s.verify"\n [ Packets: 3 Bytes: 12 ]\n' "$ANCHOR_NAME" > "$FIXTURE/verbose.rules"; [ "$(verify_rule_packets)" = 3 ]""")

    def test_missing_verify_label_is_not_evidence(self):
        (self.root / 'verbose.rules').write_text('@0 block drop out quick\n [ Packets: 99 Bytes: 0 ]\n')
        self.shell('[ -z "$(verify_rule_packets)" ]')

    def test_uninstall_rejects_live_anchor_reference(self):
        self.shell('assert_secure_installation_paths() { :; }; BACKUP_DIR="$FIXTURE/backups"; STATE_FILE="$FIXTURE/no-state"; INSTALL_PATH="$FIXTURE/installed"; uninstall_rules', expected=1)
        self.assertTrue((self.root / 'anchor').exists())

    def run_verify(self, mode, expected):
        # Exercise the complete verifier, including the EXIT cleanup, while
        # keeping all sockets, routes and pf mutations inside the fixture.
        body = r'''
assert_secure_installation_paths() { :; }
make_temp_dir() { mkdir "$FIXTURE/probe"; printf '%s\n' "$FIXTURE/probe"; }
BAIT_CANDIDATES="192.0.2.1:443"
fake_route() {
  printf '%s\n' "$*" >> "$FIXTURE/route.calls"
  case "$*" in
    '-n get default') printf 'interface: en0\ngateway: 192.0.2.254\n' ;;
    *'add -host'*) touch "$FIXTURE/route-present" ;;
    *'get -host'*)
      if [ -f "$FIXTURE/route-present" ]; then
        printf 'destination: %s\ngateway: %s\ninterface: en0\nflags: <UP,GATEWAY,HOST,STATIC,IFSCOPE>\n' "$VERIFY_ADDRESS" "$VERIFY_GATEWAY"
      else printf 'destination: default\n'; fi ;;
    *'delete -host'*)
      [ "$MODE" != cleanup-fails ] || return 1
      rm -f "$FIXTURE/route-present" ;;
    *) return 1 ;;
  esac
}
fake_nc() {
  printf 'probe\n' >> "$FIXTURE/nc.calls"
  case "$MODE" in baseline-fails) return 1 ;; esac
  count=$(wc -l < "$FIXTURE/nc.calls")
  [ "$count" -ne 2 ] || return 1
  if [ "$count" -eq 3 ] && [ "$MODE" = restore-fails ]; then return 1; fi
}
verify_rule_packets() {
  case "$MODE" in no-hit) printf '0\n' ;; missing-counter) : ;; *) printf '3\n' ;; esac
}
trap 'finish "$?"' EXIT
verify_rules
'''
        out = self.shell('MODE=' + shlex.quote(mode) + '\n' + body, expected)
        if mode != 'cleanup-fails':
            self.assertFalse((self.root / 'route-present').exists())
        self.assertFalse((self.root / 'probe').exists())
        return out

    def test_full_verify_success_requires_restore_and_cleanup(self):
        out = self.run_verify('success', 0)
        self.assertIn('实测通过', out)
        self.assertEqual(len((self.root / 'nc.calls').read_text().splitlines()), 3)

    def test_full_verify_unreachable_baseline_is_unverified(self):
        self.assertNotIn('实测通过', self.run_verify('baseline-fails', 2))

    def test_full_verify_zero_hits_is_unverified(self):
        self.assertNotIn('实测通过', self.run_verify('no-hit', 2))

    def test_full_verify_missing_counter_is_unverified(self):
        self.assertNotIn('实测通过', self.run_verify('missing-counter', 2))

    def test_full_verify_restored_baseline_failure_is_failure(self):
        self.assertNotIn('实测通过', self.run_verify('restore-fails', 1))

    def test_full_verify_cleanup_failure_cannot_report_success(self):
        self.assertNotIn('实测通过', self.run_verify('cleanup-fails', 1))


if __name__ == '__main__':
    unittest.main(verbosity=2)
