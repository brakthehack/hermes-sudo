"""Tests for hermes-sudo: _command_has_real_sudo and helpers."""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import _command_has_real_sudo, _command_needs_confirm


# ---------------------------------------------------------------------------
# _command_has_real_sudo
# ---------------------------------------------------------------------------

class TestCommandHasRealSudo:

    # --- True positives (cases that MUST be detected) ---

    def test_bare_sudo(self):
        assert _command_has_real_sudo("sudo whoami") is True

    def test_sudo_with_flags(self):
        assert _command_has_real_sudo("sudo -u root whoami") is True
        assert _command_has_real_sudo("sudo -E env") is True

    def test_env_assignment_before_sudo(self):
        assert _command_has_real_sudo("DEBUG=1 sudo whoami") is True
        assert _command_has_real_sudo("PATH=/usr/bin sudo cmd") is True

    def test_chain_operator_and(self):
        assert _command_has_real_sudo("cmd1 && sudo cmd2") is True

    def test_chain_operator_or(self):
        assert _command_has_real_sudo("cmd1 || sudo cmd2") is True

    def test_semicolon_separator(self):
        assert _command_has_real_sudo("cmd1; sudo cmd2") is True

    def test_pipe(self):
        assert _command_has_real_sudo("cmd1 | sudo cmd2") is True

    def test_newline(self):
        assert _command_has_real_sudo("cmd1\nsudo cmd2") is True

    def test_background(self):
        assert _command_has_real_sudo("cmd1 & sudo cmd2") is True

    def test_sudo_in_subshell(self):
        assert _command_has_real_sudo("(sudo whoami)") is True
        assert _command_has_real_sudo("(cd /tmp && sudo whoami)") is True
        assert _command_has_real_sudo("(sudo whoami; echo done)") is True

    def test_sudo_in_command_substitution(self):
        assert _command_has_real_sudo("echo $(sudo whoami)") is True
        assert _command_has_real_sudo("cat $(sudo ls /root)") is True

    def test_quoted_sudo_at_command_start(self):
        assert _command_has_real_sudo("'sudo' whoami") is True
        assert _command_has_real_sudo('"sudo" whoami') is True

    def test_prefix_command_time(self):
        assert _command_has_real_sudo("time sudo whoami") is True

    def test_prefix_command_nohup(self):
        assert _command_has_real_sudo("nohup sudo whoami") is True

    def test_prefix_command_exec(self):
        assert _command_has_real_sudo("exec sudo whoami") is True

    def test_prefix_command_env(self):
        assert _command_has_real_sudo("env sudo whoami") is True

    def test_prefix_command_nice(self):
        assert _command_has_real_sudo("nice sudo whoami") is True

    def test_prefix_command_ionice(self):
        assert _command_has_real_sudo("ionice sudo whoami") is True

    def test_prefix_command_stdbuf(self):
        assert _command_has_real_sudo("stdbuf -oL sudo whoami") is True

    def test_prefix_command_command_is_a_prefix(self):
        assert _command_has_real_sudo("command sudo whoami") is True

    def test_prefix_command_setsid(self):
        assert _command_has_real_sudo("setsid sudo whoami") is True

    def test_prefix_command_taskset(self):
        assert _command_has_real_sudo("taskset -c 0 sudo whoami") is True

    def test_sudo_with_mixed_quotes(self):
        assert _command_has_real_sudo("sudo 'whoami'") is True
        assert _command_has_real_sudo('sudo "whoami"') is True

    def test_sudo_after_env_var_with_value(self):
        assert _command_has_real_sudo("DEBUG=1 FOO=bar sudo cmd") is True

    def test_sudo_in_nested_subshells(self):
        assert _command_has_real_sudo("echo $(( 1 + 1 )) && (sudo whoami)") is True
        assert _command_has_real_sudo("echo $(echo $(sudo whoami))") is True

    # --- True negatives (cases that MUST NOT be detected) ---

    def test_echo_sudo(self):
        assert _command_has_real_sudo('echo "sudo"') is False

    def test_rg_sudo(self):
        assert _command_has_real_sudo("rg 'sudo' file") is False

    def test_man_sudo(self):
        assert _command_has_real_sudo("man sudo") is False

    def test_type_sudo(self):
        assert _command_has_real_sudo("type sudo") is False

    def test_which_sudo(self):
        assert _command_has_real_sudo("which sudo") is False

    def test_command_v_sudo(self):
        assert _command_has_real_sudo("command -v sudo") is False

    def test_sudo_as_argument(self):
        assert _command_has_real_sudo("echo foo sudo bar") is False

    def test_sudo_in_variable_assignment_value(self):
        assert _command_has_real_sudo("VAR='sudo' echo hi") is False

    def test_sudo_in_double_quoted_assignment(self):
        assert _command_has_real_sudo('VAR="sudo" echo hi') is False

    def test_path_usr_bin_sudo(self):
        assert _command_has_real_sudo("PATH=/usr/bin/sudo cmd") is False

    def test_sudo_in_function_name(self):
        assert _command_has_real_sudo("sudo-wrapper.sh cmd") is False

    def test_empty_command(self):
        assert _command_has_real_sudo("") is False

    def test_whitespace_only(self):
        assert _command_has_real_sudo("   \t  ") is False

    def test_comment_start_line_contains_sudo(self):
        assert _command_has_real_sudo("# sudo whoami") is False

    def test_comment_mid_line_sudo(self):
        assert _command_has_real_sudo("echo foo # sudo whoami") is False

    def test_sudo_in_here_string(self):
        assert _command_has_real_sudo("cat <<< sudo") is False

    def test_heredoc_body_contains_sudo_not_flagged(self):
        cmd = "cat <<EOF\nsudo\nEOF"
        assert _command_has_real_sudo(cmd) is False

    def test_heredoc_multi_line_contains_sudo_not_flagged(self):
        cmd = "cat <<EOF\nline1\nsudo whoami\nline3\nEOF"
        assert _command_has_real_sudo(cmd) is False

    def test_heredoc_tab_prefix(self):
        cmd = "cat <<-EOF\n\tsudo\n\tEOF"
        assert _command_has_real_sudo(cmd) is False

    def test_heredoc_quoted_delimiter(self):
        cmd = "cat <<'EOF'\nsudo\nEOF"
        assert _command_has_real_sudo(cmd) is False

    def test_heredoc_with_command_after(self):
        cmd = "cat <<EOF\nbody\nEOF\nsudo whoami"
        assert _command_has_real_sudo(cmd) is True

    def test_heredoc_separate_delimiter_token(self):
        cmd = "cat << EOF\nsudo\nEOF"
        assert _command_has_real_sudo(cmd) is False

    def test_arithmetic_expansion_not_sudo(self):
        assert _command_has_real_sudo("echo $(( 1 + 1 ))") is False
        assert _command_has_real_sudo("echo $(( 1 + 1 )) && echo foo") is False

    def test_operator_2_and_1_not_background(self):
        assert _command_has_real_sudo("sudo whoami 2>&1") is True

    # --- Edge cases ---

    def test_multiple_sudo_occurrences(self):
        assert _command_has_real_sudo("sudo cmd1 && sudo cmd2") is True

    def test_nested_parentheses_no_sudo(self):
        assert _command_has_real_sudo("(echo hello)") is False

    def test_escaped_newline(self):
        assert _command_has_real_sudo("sudo\\\nwhoami") is True

    def test_comment_only_line_after_background(self):
        assert _command_has_real_sudo("cmd1 &#\nsudo whoami") is True


# ---------------------------------------------------------------------------
# _command_needs_confirm — destructive command detection
# ---------------------------------------------------------------------------

class TestCommandNeedsConfirm:

    def test_rm(self):
        assert _command_needs_confirm("sudo rm -rf /") is True

    def test_dd(self):
        assert _command_needs_confirm("sudo dd if=/dev/zero of=/dev/sda") is True

    def test_mkfs(self):
        assert _command_needs_confirm("sudo mkfs.ext4 /dev/sdb1") is True

    def test_shutdown(self):
        assert _command_needs_confirm("sudo shutdown -h now") is True

    def test_reboot(self):
        assert _command_needs_confirm("sudo reboot") is True

    def test_chmod_system(self):
        assert _command_needs_confirm("sudo chmod 777 /etc/shadow") is True

    def test_apt_not_flagged(self):
        assert _command_needs_confirm("sudo apt install nginx") is False

    def test_systemctl_not_flagged(self):
        assert _command_needs_confirm("sudo systemctl restart nginx") is False

    def test_useradd_not_flagged(self):
        assert _command_needs_confirm("sudo useradd alice") is False

    def test_no_trigger_in_string(self):
        assert _command_needs_confirm("echo rm") is False

    def test_no_trigger_in_argument(self):
        assert _command_needs_confirm("grep -r rm /etc") is False

    def test_multiple_commands_only_first_triggers(self):
        assert _command_needs_confirm("apt update && sudo rm /tmp/file") is True

    def test_chown(self):
        assert _command_needs_confirm("sudo chown root:root /etc/crontab") is True

    def test_mv_self_not_flagged(self):
        assert _command_needs_confirm("sudo mv /etc/passwd /tmp/") is False

    def test_cp_self_not_flagged(self):
        assert _command_needs_confirm("sudo cp /tmp/backdoor /usr/bin/") is False

    def test_quoted_rm_in_string(self):
        assert _command_needs_confirm('echo "rm is dangerous"') is False

    def test_comment_rm(self):
        assert _command_needs_confirm("# rm -rf /") is False

    def test_safe_command_not_flagged(self):
        assert _command_needs_confirm("sudo whoami") is False

    def test_empty_string(self):
        assert _command_needs_confirm("") is False
    # --- Regression tests for critical bypasses (C4-C7) ---

    def test_c4_prefix_time_bypass(self):
        """C4: time sudo rm must be detected"""
        assert _command_needs_confirm("time sudo rm -rf /") is True

    def test_c4_prefix_nice_bypass(self):
        """C4: nice sudo rm must be detected"""
        assert _command_needs_confirm("nice sudo rm -rf /") is True

    def test_c4_prefix_nohup_bypass(self):
        """C4: nohup sudo rm must be detected"""
        assert _command_needs_confirm("nohup sudo rm -rf /") is True

    def test_c4_prefix_exec_bypass(self):
        """C4: exec sudo rm must be detected"""
        assert _command_needs_confirm("exec sudo rm -rf /") is True

    def test_c4_prefix_env_bypass(self):
        """C4: env sudo rm must be detected"""
        assert _command_needs_confirm("env sudo rm -rf /") is True

    def test_c4_prefix_ionice_bypass(self):
        """C4: ionice sudo rm must be detected"""
        assert _command_needs_confirm("ionice sudo rm -rf /") is True

    def test_c4_prefix_stdbuf_bypass(self):
        """C4: stdbuf sudo rm must be detected"""
        assert _command_needs_confirm("stdbuf sudo rm -rf /") is True

    def test_c4_prefix_setsid_bypass(self):
        """C4: setsid sudo rm must be detected"""
        assert _command_needs_confirm("setsid sudo rm -rf /") is True

    def test_c4_prefix_taskset_bypass(self):
        """C4: taskset sudo rm must be detected"""
        assert _command_needs_confirm("taskset sudo rm -rf /") is True

    def test_c4_prefix_chrt_bypass(self):
        """C4: chrt sudo rm must be detected"""
        assert _command_needs_confirm("chrt sudo rm -rf /") is True

    def test_c5_subshell_bypass(self):
        """C5: (sudo rm -rf /) must be detected"""
        assert _command_needs_confirm("(sudo rm -rf /)") is True

    def test_c5_nested_subshell_bypass(self):
        """C5: nested subshells must be detected"""
        assert _command_needs_confirm("((sudo rm -rf /))") is True

    def test_c5_subshell_with_pipes(self):
        """C5: subshell with pipe must be detected"""
        assert _command_needs_confirm("(echo yes | sudo dd if=/dev/zero of=/dev/sda)") is True

    def test_c6_command_substitution_bypass(self):
        """C6: echo $(sudo rm -rf /) must be detected"""
        assert _command_needs_confirm("echo $(sudo rm -rf /)") is True

    def test_c6_nested_command_substitution(self):
        """C6: nested command substitution must be detected"""
        assert _command_needs_confirm("echo $(echo $(sudo rm -rf /))") is True

    def test_c6_backtick_substitution(self):
        """C6: backtick substitution must be detected"""
        assert _command_needs_confirm("echo `sudo rm -rf /`") is True

    def test_c7_env_assignment_bypass(self):
        """C7: DEBUG=1 sudo rm must be detected"""
        assert _command_needs_confirm("DEBUG=1 sudo rm -rf /") is True

    def test_c7_multiple_env_assignments(self):
        """C7: multiple env assignments before sudo rm"""
        assert _command_needs_confirm("DEBUG=1 FOO=bar sudo rm -rf /") is True

    def test_c7_env_before_prefix_before_sudo(self):
        """C7: env assignment before prefix before sudo"""
        assert _command_needs_confirm("DEBUG=1 time sudo rm -rf /") is True

    # --- Regression tests for L1 (&&/||) ---

    def test_l1_and_chain(self):
        """L1: cmd1 && sudo rm must be detected"""
        assert _command_needs_confirm("cmd1 && sudo rm -rf /") is True

    def test_l1_or_chain(self):
        """L1: cmd1 || sudo rm must be detected"""
        assert _command_needs_confirm("cmd1 || sudo rm -rf /") is True

    def test_l1_chain_without_sudo(self):
        """L1: chain without sudo must still be detected"""
        assert _command_needs_confirm("cmd1 && rm -rf /") is True

    # --- Regression tests for L3 (backslash continuation) ---

    def test_l3_backslash_continuation(self):
        """L3: sudo rm \\n-rf / must be detected"""
        assert _command_needs_confirm("sudo rm \\\n-rf /") is True

    def test_l3_backslash_before_rm(self):
        """L3: \\nrm -rf / must be detected"""
        assert _command_needs_confirm("\\\nrm -rf /") is True


# ---------------------------------------------------------------------------
# Regression tests for C1-C3, H1
# ---------------------------------------------------------------------------

class TestCriticalBypasses:
    """Regression tests for critical security bypasses."""

    def test_c2_command_sudo_detected(self):
        """C2: command sudo must be detected as having real sudo"""
        assert _command_has_real_sudo("command sudo whoami") is True

    def test_c2_command_v_sudo_not_detected(self):
        """C2: command -v sudo must NOT be detected (informational lookup)"""
        assert _command_has_real_sudo("command -v sudo") is False

    def test_c2_command_V_sudo_not_detected(self):
        """C2: command -V sudo must NOT be detected (informational lookup)"""
        assert _command_has_real_sudo("command -V sudo") is False

    def test_c3_backslash_escaped_sudo(self):
        """C3: \\sudo must be detected as having real sudo"""
        assert _command_has_real_sudo(r"\sudo whoami") is True

    def test_c3_multiple_backslashes(self):
        r"""C3: \\sudo must be detected as having real sudo"""
        assert _command_has_real_sudo(r"\\sudo whoami") is True

    def test_h1_heredoc_false_positive(self):
        """H1: foo<<bar must NOT be detected as sudo"""
        assert _command_has_real_sudo("foo<<bar") is False

    def test_h1_heredoc_in_middle_of_token(self):
        """H1: token with << in middle must not trigger heredoc handling"""
        assert _command_has_real_sudo("echo foo<<bar") is False


# ---------------------------------------------------------------------------
# L4: Tests for untested _CONFIRM_TRIGGERS
# ---------------------------------------------------------------------------

class TestUntestedConfirmTriggers:
    """Tests for _CONFIRM_TRIGGERS that previously had no coverage."""

    def test_fdisk(self):
        assert _command_needs_confirm("sudo fdisk /dev/sda") is True

    def test_format(self):
        assert _command_needs_confirm("sudo format /dev/sdb") is True

    def test_poweroff(self):
        assert _command_needs_confirm("sudo poweroff") is True

    def test_halt(self):
        assert _command_needs_confirm("sudo halt") is True

    def test_init(self):
        assert _command_needs_confirm("sudo init 0") is True


# ---------------------------------------------------------------------------
# H8: Lifecycle hook tests
# ---------------------------------------------------------------------------

class TestLifecycleHooks:
    """Basic unit tests for lifecycle hooks and state management."""

    def test_reset_state_clears_sudo_scope(self):
        from tools import _reset_state, _sudo_scope, _sudo_consumed
        import tools
        tools._sudo_scope = "session"
        tools._sudo_consumed = True
        _reset_state()
        assert tools._sudo_scope is None
        assert tools._sudo_consumed is False

    def test_reset_state_clears_once_scope(self):
        from tools import _reset_state, _sudo_scope, _sudo_consumed
        import tools
        tools._sudo_scope = "once"
        tools._sudo_consumed = False
        _reset_state()
        assert tools._sudo_scope is None
        assert tools._sudo_consumed is False

    def test_on_pre_tool_call_non_terminal_returns_none(self):
        from tools import _on_pre_tool_call
        result = _on_pre_tool_call(
            tool_name="file_read",
            arguments={"path": "/tmp/test"},
            session_id="test-session",
        )
        assert result is None

    def test_on_pre_tool_call_no_sudo_scope_returns_none(self):
        from tools import _on_pre_tool_call, _reset_state
        import tools
        _reset_state()
        result = _on_pre_tool_call(
            tool_name="terminal",
            arguments={"command": "ls /tmp"},
            session_id="test-session",
        )
        assert result is None

    def test_on_post_tool_call_terminal_without_sudo_marks_consumed(self):
        from tools import _on_post_tool_call, _handle_sudo_authorize
        import tools
        tools._sudo_scope = "once"
        tools._sudo_consumed = False
        _on_post_tool_call(
            tool_name="terminal",
            args={"command": "sudo ls /tmp"},
            result="file1\nfile2",
            session_id="test-session",
        )
        assert tools._sudo_consumed is True

    def test_on_session_end_resets_state(self):
        from tools import _on_session_end, _reset_state
        import tools
        _reset_state()
        tools._sudo_scope = "session"
        tools._sudo_consumed = False
        _on_session_end(session_id="test-session")
        assert tools._sudo_scope is None
        assert tools._sudo_consumed is False

    def test_on_session_end_runs_sudo_k(self):
        """Verify _on_session_end calls _run_sudo_k (audit log entry created)."""
        from tools import _on_session_end, _reset_state, _AUDIT_LOG
        import tools
        _reset_state()
        tools._sudo_scope = "session"
        _on_session_end(session_id="test-session")
        # Check audit log was written
        import os
        assert os.path.exists(_AUDIT_LOG)


# ---------------------------------------------------------------------------
# Batch authorization tests
# ---------------------------------------------------------------------------

class TestBatchAuthorization:
    """Tests for batch scope authorization (#6)."""

    def test_batch_requires_count(self):
        from tools import _handle_sudo_authorize, _reset_state
        import tools
        _reset_state()
        result = json.loads(_handle_sudo_authorize(scope="batch"))
        assert "error" in result
        assert "count" in result["error"]

    def test_batch_count_too_high(self):
        from tools import _handle_sudo_authorize, _reset_state
        _reset_state()
        # Mock _sudo_nopasswd_works to avoid password prompt
        import tools
        orig = tools._sudo_nopasswd_works
        tools._sudo_nopasswd_works = lambda: False
        try:
            result = json.loads(_handle_sudo_authorize(scope="batch", count=101))
            assert "error" in result
            assert "100" in result["error"]
        finally:
            tools._sudo_nopasswd_works = orig

    def test_batch_sets_remaining_count(self):
        from tools import _handle_sudo_authorize, _reset_state
        import tools
        _reset_state()
        orig = tools._sudo_nopasswd_works
        tools._sudo_nopasswd_works = lambda: True
        try:
            result = json.loads(_handle_sudo_authorize(scope="batch", count=5))
            assert result["success"] is True
            assert result["scope"] == "batch"
            assert tools._sudo_batch_remaining == 5
        finally:
            tools._sudo_nopasswd_works = orig

    def test_batch_pre_blocks_when_exhausted(self):
        from tools import _on_pre_tool_call, _reset_state
        import tools
        _reset_state()
        tools._sudo_scope = "batch"
        tools._sudo_batch_remaining = 0
        result = _on_pre_tool_call(
            tool_name="terminal",
            args={"command": "sudo ls /tmp"},
            session_id="test",
        )
        assert result["action"] == "block"
        assert "exhausted" in result["message"]

    def test_batch_pre_allows_when_remaining(self):
        from tools import _on_pre_tool_call, _reset_state
        import tools
        _reset_state()
        tools._sudo_scope = "batch"
        tools._sudo_batch_remaining = 3
        tools._sudo_timestamp_valid = lambda: True
        result = _on_pre_tool_call(
            tool_name="terminal",
            args={"command": "sudo ls /tmp"},
            session_id="test",
        )
        assert result is None  # allowed through

    def test_batch_pre_blocks_destructive(self):
        from tools import _on_pre_tool_call, _reset_state
        import tools
        _reset_state()
        tools._sudo_scope = "batch"
        tools._sudo_batch_remaining = 3
        tools._sudo_timestamp_valid = lambda: True
        result = _on_pre_tool_call(
            tool_name="terminal",
            args={"command": "sudo rm -rf /"},
            session_id="test",
        )
        assert result["action"] == "block"
        assert "destructive" in result["message"]

    def test_batch_post_decrements_counter(self):
        from tools import _on_post_tool_call, _reset_state
        import tools
        _reset_state()
        tools._sudo_scope = "batch"
        tools._sudo_batch_remaining = 3
        _on_post_tool_call(
            tool_name="terminal",
            args={"command": "sudo ls /tmp"},
            result="file1\nfile2",
            session_id="test",
        )
        assert tools._sudo_batch_remaining == 2

    def test_batch_post_clears_when_zero(self):
        from tools import _on_post_tool_call, _reset_state
        import tools
        _reset_state()
        tools._sudo_scope = "batch"
        tools._sudo_batch_remaining = 1
        _on_post_tool_call(
            tool_name="terminal",
            args={"command": "sudo ls /tmp"},
            result="file1\nfile2",
            session_id="test",
        )
        assert tools._sudo_batch_remaining == 0


# ---------------------------------------------------------------------------
# Status query tests
# ---------------------------------------------------------------------------

class TestStatusQuery:
    """Tests for status query (#1)."""

    def test_status_no_auth(self):
        from tools import _handle_sudo_authorize, _reset_state
        _reset_state()
        import tools
        orig = tools._sudo_nopasswd_works
        tools._sudo_nopasswd_works = lambda: False
        try:
            result = json.loads(_handle_sudo_authorize(scope="status"))
            assert result["scope"] == "none"
            assert result["consumed"] is False
            assert result["nopasswd"] is False
        finally:
            tools._sudo_nopasswd_works = orig

    def test_status_with_session_scope(self):
        from tools import _handle_sudo_authorize, _reset_state
        import tools
        _reset_state()
        tools._sudo_scope = "session"
        tools._sudo_consumed = False
        orig = tools._sudo_nopasswd_works
        tools._sudo_nopasswd_works = lambda: False
        try:
            result = json.loads(_handle_sudo_authorize(scope="status"))
            assert result["scope"] == "session"
            assert result["consumed"] is False
        finally:
            tools._sudo_nopasswd_works = orig

    def test_status_with_batch_scope(self):
        from tools import _handle_sudo_authorize, _reset_state
        import tools
        _reset_state()
        tools._sudo_scope = "batch"
        tools._sudo_batch_remaining = 3
        orig = tools._sudo_nopasswd_works
        tools._sudo_nopasswd_works = lambda: False
        try:
            result = json.loads(_handle_sudo_authorize(scope="status"))
            assert result["scope"] == "batch"
            assert result["batch_remaining"] == 3
        finally:
            tools._sudo_nopasswd_works = orig

    def test_status_nopasswd_indicator(self):
        from tools import _handle_sudo_authorize, _reset_state
        import tools
        _reset_state()
        orig = tools._sudo_nopasswd_works
        tools._sudo_nopasswd_works = lambda: True
        try:
            result = json.loads(_handle_sudo_authorize(scope="status"))
            assert result["nopasswd"] is True
            assert "NOPASSWD" in result.get("message", "")
        finally:
            tools._sudo_nopasswd_works = orig


# ---------------------------------------------------------------------------
# NOPASSWD feedback tests
# ---------------------------------------------------------------------------

class TestNOPASSWDFeedback:
    """Tests for NOPASSWD feedback (#8)."""

    def test_nopasswd_in_authorize_message(self):
        from tools import _handle_sudo_authorize, _reset_state
        import tools
        _reset_state()
        orig = tools._sudo_nopasswd_works
        tools._sudo_nopasswd_works = lambda: True
        try:
            result = json.loads(_handle_sudo_authorize(scope="once"))
            assert result["success"] is True
            assert "NOPASSWD" in result["message"]
        finally:
            tools._sudo_nopasswd_works = orig

    def test_nopasswd_in_batch_authorize_message(self):
        from tools import _handle_sudo_authorize, _reset_state
        import tools
        _reset_state()
        orig = tools._sudo_nopasswd_works
        tools._sudo_nopasswd_works = lambda: True
        try:
            result = json.loads(_handle_sudo_authorize(scope="batch", count=5))
            assert result["success"] is True
            assert "NOPASSWD" in result["message"]
            assert "batch" in result["message"].lower()
        finally:
            tools._sudo_nopasswd_works = orig
