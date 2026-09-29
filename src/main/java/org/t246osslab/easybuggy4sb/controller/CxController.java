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
import java.util.List;

@RestController
public class CxController {

    /**
     * Allowlist of commands that may be executed via the legacy endpoint.
     * Only these exact command names are permitted; no shell interpretation occurs
     * because ProcessBuilder receives a pre-split argument list (shell=false equivalent).
     */
    private static final List<String> ALLOWED_COMMANDS = Collections.unmodifiableList(
            Arrays.asList("whoami", "date", "hostname", "uptime"));

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

    // curl localhost:8080/legacy/runCommand/whoami
    @PostMapping("legacy/runCommand/{cmd}")
    public String runCommand(@PathVariable String cmd) throws IOException {
        // Validate cmd against a strict allowlist before execution.
        // ProcessBuilder receives an explicit argument list (not a shell string),
        // so no shell metacharacter interpretation takes place.
        if (!ALLOWED_COMMANDS.contains(cmd)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Command not allowed");
        }
        byte[] buf = new byte[1024];
        // Safe: cmd is an exact match from the allowlist; no shell is involved.
        Process process = new ProcessBuilder(cmd).start();
        int len = process.getInputStream().read(buf);
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
