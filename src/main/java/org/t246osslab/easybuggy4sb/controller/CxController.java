package org.t246osslab.easybuggy4sb.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import springfox.documentation.annotations.ApiIgnore;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import java.util.HashSet;

@RestController
public class CxController {

    /**
     * Allowlist of commands permitted by this legacy endpoint.
     * Only these exact, hardcoded command strings may be executed.
     * Shell metacharacters and arbitrary user-supplied commands are rejected.
     */
    private static final Set<String> ALLOWED_COMMANDS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("whoami", "hostname", "date", "uptime")));

    @GetMapping("v2/authed/getTime") // require auth
    public String getTime() {
        return new Date().toString();
    }

    @GetMapping("v2/authed/getUser") // require auth
    public String getUser() {
        return "user is: " + System.getProperty("user.name");
    }

    @GetMapping("v2/authed/getIP") // require auth
    public String getIP() throws UnknownHostException {
        return Inet4Address.getLocalHost().getHostAddress();
    }

    @ApiIgnore // don't want this in openapi file
    @GetMapping("v2/authed/multiply") // require auth
    public int multiply(@RequestParam(name = "a") int a, @RequestParam(name = "b") int b) {
        return a * b;
    }

    // curl -X POST localhost:8080/legacy/runCommand/whoami
    // Only commands in ALLOWED_COMMANDS may be executed.
    @PostMapping("legacy/runCommand/{cmd}")
    public String runCommand(@PathVariable String cmd) throws IOException {
        // Validate against allowlist before executing — reject anything not explicitly permitted.
        // ProcessBuilder is invoked with a List<String> (no shell interpreter) so shell
        // metacharacters in the command string have no effect even if validation were bypassed.
        if (!ALLOWED_COMMANDS.contains(cmd)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Command not permitted");
        }
        // Use ProcessBuilder with an explicit argument list (shell=false equivalent in Java).
        // The command is a hardcoded value from the allowlist — no user-controlled data
        // is passed as a shell string, preventing command injection.
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        byte[] buf = new byte[1024];
        int len = pb.start().getInputStream().read(buf);
        return new String(buf, 0, len);
    }

    @GetMapping("legacy/add")
    public int add(@RequestParam(name = "a") int a, @RequestParam(name = "b") int b) {
        return a + b;
    }

    @GetMapping("internal")
    public String internal() {
        return "this is an internal api";
    }

    @GetMapping("internal/op1")
    public String op1() {
        return "op1 api";
    }

    @PostMapping("internal/op2")
    public String op2() {
        return "op2 api";
    }
}
