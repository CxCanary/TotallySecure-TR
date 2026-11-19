package org.t246osslab.easybuggy4sb.controller;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class CxControllerTest {

    private final CxController controller = new CxController();

    @Test
    public void allowedCommandIsExecuted() throws IOException {
        String result = controller.runCommand("whoami");
        assertFalse(result.trim().isEmpty());
    }

    @Test
    public void arbitraryCommandsAreRejected() throws IOException {
        String[] payloads = {
            "ls", "id", "cat /etc/passwd", "whoami; id", "whoami && id",
            "whoami | id", "$(id)", "`id`", "whoami\nid", "../../bin/sh", ""
        };
        for (String payload : payloads) {
            assertRejected(payload);
        }
    }

    @Test
    public void injectedCommandHasNoSideEffects() throws IOException {
        Path marker = Paths.get(System.getProperty("java.io.tmpdir"), "cx_injection_marker_" + System.nanoTime());
        try {
            assertRejected("touch " + marker);
            assertRejected("whoami; touch " + marker);
            assertEquals(false, Files.exists(marker));
        } finally {
            Files.deleteIfExists(marker);
        }
    }

    private void assertRejected(String payload) throws IOException {
        try {
            controller.runCommand(payload);
            fail("Command should have been rejected: " + payload);
        } catch (ResponseStatusException e) {
            assertEquals(HttpStatus.BAD_REQUEST, e.getStatus());
        }
    }
}
