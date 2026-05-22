"""Tests for hermes-sudo: _command_has_real_sudo and helpers."""
import sys
import os

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

    def test_prefix_command_command_is_not_a_prefix(self):
        assert _command_has_real_sudo("command sudo whoami") is False

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
