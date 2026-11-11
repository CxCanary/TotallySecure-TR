package org.t246osslab.easybuggy4sb.controller;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;

import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class CxControllerTest {

    private final CxController controller = new CxController();

    @Test
    public void allowedCommandRuns() throws IOException {
        String out = controller.runCommand("whoami");
        assertFalse(out.trim().isEmpty());
    }

    @Test
    public void injectedCommandsAreRejected() throws IOException {
        File marker = new File(System.getProperty("java.io.tmpdir"), "cx_injection_marker");
        marker.delete();
        String[] payloads = {
            "touch " + marker.getAbsolutePath(),
            "whoami; touch " + marker.getAbsolutePath(),
            "whoami && id",
            "whoami | cat",
            "$(id)",
            "id",
            ""
        };
        for (String payload : payloads) {
            try {
                controller.runCommand(payload);
                fail("Expected rejection for: " + payload);
            } catch (ResponseStatusException e) {
                assertEquals(HttpStatus.BAD_REQUEST, e.getStatus());
            }
        }
        assertTrue(!marker.exists());
    }
}
