"""Tests for hermes-sudo: _command_has_real_sudo and helpers."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import _command_has_real_sudo


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
        """BUG #1: subshell-wrapped sudo must be detected."""
        assert _command_has_real_sudo("(sudo whoami)") is True
        assert _command_has_real_sudo("(cd /tmp && sudo whoami)") is True
        assert _command_has_real_sudo("(sudo whoami; echo done)") is True

    def test_sudo_in_command_substitution(self):
        """BUG #1: $(...) command substitution must be detected."""
        assert _command_has_real_sudo("echo $(sudo whoami)") is True
        assert _command_has_real_sudo("cat $(sudo ls /root)") is True

    def test_quoted_sudo_at_command_start(self):
        """BUG #3: quoted 'sudo' at command-start is a real execution."""
        assert _command_has_real_sudo("'sudo' whoami") is True
        assert _command_has_real_sudo('"sudo" whoami') is True

    def test_prefix_command_time(self):
        """BUG #4: time sudo must be detected."""
        assert _command_has_real_sudo("time sudo whoami") is True

    def test_prefix_command_nohup(self):
        """BUG #4: nohup sudo must be detected."""
        assert _command_has_real_sudo("nohup sudo whoami") is True

    def test_prefix_command_exec(self):
        """BUG #4: exec sudo must be detected."""
        assert _command_has_real_sudo("exec sudo whoami") is True

    def test_prefix_command_env(self):
        """BUG #4: env sudo must be detected."""
        assert _command_has_real_sudo("env sudo whoami") is True

    def test_prefix_command_nice(self):
        """BUG #4: nice sudo must be detected."""
        assert _command_has_real_sudo("nice sudo whoami") is True

    def test_prefix_command_ionice(self):
        """BUG #4: ionice sudo must be detected."""
        assert _command_has_real_sudo("ionice sudo whoami") is True

    def test_prefix_command_stdbuf(self):
        """BUG #4: stdbuf sudo must be detected."""
        assert _command_has_real_sudo("stdbuf -oL sudo whoami") is True

    def test_prefix_command_command_is_not_a_prefix(self):
        """command sudo whoami is no longer a detected prefix."""
        assert _command_has_real_sudo("command sudo whoami") is False

    def test_prefix_command_setsid(self):
        """BUG #4: setsid sudo must be detected."""
        assert _command_has_real_sudo("setsid sudo whoami") is True

    def test_prefix_command_taskset(self):
        """BUG #4: taskset sudo must be detected."""
        assert _command_has_real_sudo("taskset -c 0 sudo whoami") is True

    def test_sudo_with_mixed_quotes(self):
        """sudo detection must not be confused by quoting around args."""
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
        """VAR='sudo' cmd must not flag sudo (it's a value, not a command)."""
        assert _command_has_real_sudo("VAR='sudo' echo hi") is False

    def test_sudo_in_double_quoted_assignment(self):
        assert _command_has_real_sudo('VAR="sudo" echo hi') is False

    def test_path_usr_bin_sudo(self):
        assert _command_has_real_sudo("PATH=/usr/bin/sudo cmd") is False

    def test_sudo_in_function_name(self):
        """A function named sudo-something is not the sudo command."""
        assert _command_has_real_sudo("sudo-wrapper.sh cmd") is False

    def test_empty_command(self):
        assert _command_has_real_sudo("") is False

    def test_whitespace_only(self):
        assert _command_has_real_sudo("   \t  ") is False

    def test_comment_start_line_contains_sudo(self):
        """# sudo must not be flagged — comment at start of line."""
        assert _command_has_real_sudo("# sudo whoami") is False

    def test_comment_mid_line_sudo(self):
        """echo foo # sudo must not flag sudo (in comment)."""
        assert _command_has_real_sudo("echo foo # sudo whoami") is False

    def test_sudo_in_here_string(self):
        """BUG #5: <<< here-string is not a heredoc — sudo may appear."""
        # Here-string content is inline, not a body. The parser should not skip
        # the rest of the command after <<<.
        assert _command_has_real_sudo("cat <<< sudo") is False

    def test_heredoc_body_contains_sudo_not_flagged(self):
        """BUG #5: 'sudo' inside heredoc body must NOT be flagged."""
        cmd = "cat <<EOF\nsudo\nEOF"
        assert _command_has_real_sudo(cmd) is False

    def test_heredoc_multi_line_contains_sudo_not_flagged(self):
        """BUG #5: multiple lines with sudo in heredoc body."""
        cmd = "cat <<EOF\nline1\nsudo whoami\nline3\nEOF"
        assert _command_has_real_sudo(cmd) is False

    def test_heredoc_tab_prefix(self):
        """BUG #5: <<- with tab-indented delimiter must also work."""
        cmd = "cat <<-EOF\n\tsudo\n\tEOF"
        assert _command_has_real_sudo(cmd) is False

    def test_heredoc_quoted_delimiter(self):
        """BUG #5: quoted delimiter like <<'EOF'."""
        cmd = "cat <<'EOF'\nsudo\nEOF"
        assert _command_has_real_sudo(cmd) is False

    def test_heredoc_with_command_after(self):
        """After heredoc body, a real sudo must still be detected."""
        cmd = "cat <<EOF\nbody\nEOF\nsudo whoami"
        assert _command_has_real_sudo(cmd) is True

    def test_heredoc_separate_delimiter_token(self):
        """BUG #5: << followed by space then delimiter."""
        cmd = "cat << EOF\nsudo\nEOF"
        assert _command_has_real_sudo(cmd) is False

    def test_arithmetic_expansion_not_sudo(self):
        """$(( ... )) must not cause false positives or infinite loops."""
        assert _command_has_real_sudo("echo $(( 1 + 1 ))") is False
        assert _command_has_real_sudo("echo $(( 1 + 1 )) && echo foo") is False

    def test_operator_2_and_1_not_background(self):
        """2>&1 must not break command separation (redirect, not bg)."""
        assert _command_has_real_sudo("sudo whoami 2>&1") is True
        assert _command_has_real_sudo("sudo whoami 2>&1") is True

    # --- Edge cases ---

    def test_multiple_sudo_occurrences(self):
        """First sudo should be detected and return early."""
        assert _command_has_real_sudo("sudo cmd1 && sudo cmd2") is True

    def test_nested_parentheses_no_sudo(self):
        assert _command_has_real_sudo("(echo hello)") is False

    def test_escaped_newline(self):
        """Backslash-newline line continuation."""
        assert _command_has_real_sudo("sudo\\\nwhoami") is True

    def test_comment_only_line_after_background(self):
        """# at start of command after background."""
        assert _command_has_real_sudo("cmd1 &#\nsudo whoami") is True
