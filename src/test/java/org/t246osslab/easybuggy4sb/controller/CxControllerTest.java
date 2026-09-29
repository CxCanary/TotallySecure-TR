package org.t246osslab.easybuggy4sb.controller;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for CxController that verify the command injection remediation.
 *
 * <p>The vulnerable code previously passed user-supplied path variables directly to
 * {@code Runtime.getRuntime().exec(cmd)}, allowing an attacker to execute arbitrary
 * OS commands. The fix uses an allowlist validated before a {@link ProcessBuilder}
 * call so that no shell metacharacter interpretation is possible.
 */
@RunWith(SpringRunner.class)
@WebMvcTest(CxController.class)
public class CxControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // Allowlist rejection – command injection attack vectors must return 400
    // -------------------------------------------------------------------------

    /**
     * Attempting to inject a shell separator followed by an extra command must be
     * rejected before any process is started.
     * Attack vector: {@code whoami;id}
     */
    @Test
    public void testCommandInjectionSemicolon_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami;id")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    /**
     * Attack vector using shell pipe: {@code whoami|id}
     */
    @Test
    public void testCommandInjectionPipe_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami|id")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    /**
     * Attack vector using ampersand background execution: {@code whoami&id}
     */
    @Test
    public void testCommandInjectionAmpersand_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami%26id")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    /**
     * Attempt to traverse to an arbitrary binary: {@code /bin/sh}
     */
    @Test
    public void testAbsolutePathShell_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/%2Fbin%2Fsh")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    /**
     * Attempt to read sensitive files via {@code cat /etc/passwd}.
     * Even the first token "cat" is not on the allowlist and must be rejected.
     */
    @Test
    public void testCatEtcPasswd_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/cat")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    /**
     * Completely arbitrary command that is not on the allowlist.
     */
    @Test
    public void testArbitraryCommand_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/id")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    /**
     * Empty string as cmd must also be rejected.
     */
    @Test
    public void testEmptyCommand_isRejected() throws Exception {
        // Spring MVC maps an empty path segment differently, but an explicit
        // single-space or unknown token must still be rejected.
        mockMvc.perform(post("/legacy/runCommand/unknown")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    /**
     * Command with surrounding whitespace is NOT equivalent to an allowlisted
     * command and must be rejected.
     */
    @Test
    public void testCommandWithWhitespace_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/ whoami")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    /**
     * An allowlisted command name with an appended argument must be rejected
     * because "whoami arg" does not exactly match "whoami".
     */
    @Test
    public void testAllowlistedCommandWithExtraArg_isRejected() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami%20-a")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    // -------------------------------------------------------------------------
    // Allowlisted commands – verify the endpoint still works for safe commands
    // (integration-level check; actual process output is OS-dependent so we
    //  only assert the HTTP status is 2xx, not the body content)
    // -------------------------------------------------------------------------

    /**
     * "whoami" is on the allowlist and should succeed (2xx) on a host where the
     * binary is available.
     *
     * <p>Note: this test requires the {@code whoami} binary to be present on the
     * test host. It validates that the allowlist acceptance path works end-to-end.
     */
    @Test
    public void testAllowlistedCommandWhoami_isAccepted() throws Exception {
        mockMvc.perform(post("/legacy/runCommand/whoami")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().is2xxSuccessful());
    }
}
