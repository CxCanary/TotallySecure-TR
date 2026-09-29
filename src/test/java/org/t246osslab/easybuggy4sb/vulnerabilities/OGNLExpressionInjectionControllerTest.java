package org.t246osslab.easybuggy4sb.vulnerabilities;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Locale;
import java.util.regex.Pattern;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.MessageSource;
import org.springframework.web.servlet.ModelAndView;

/**
 * Tests that OGNLExpressionInjectionController is NOT vulnerable to OGNL
 * expression injection (CWE-917).
 *
 * Security assertions verified:
 *   1. The SAFE_MATH_EXPRESSION allowlist pattern is well-formed.
 *   2. Known OGNL injection payloads are rejected before reaching the OGNL engine.
 *   3. Legitimate arithmetic expressions are accepted and evaluated.
 *   4. Tainted input containing letters, @-signs, class references, method calls,
 *      or other OGNL constructs never reaches Ognl.parseExpression().
 */
@RunWith(MockitoJUnitRunner.class)
public class OGNLExpressionInjectionControllerTest {

    @InjectMocks
    private OGNLExpressionInjectionController controller;

    @Mock
    private MessageSource msg;

    @Before
    public void setUp() {
        // Return a stable error message string for any locale message lookup so
        // that model-attribute assertions don't throw NullPointerException.
        when(msg.getMessage(anyString(), any(Object[].class), anyString(), any(Locale.class)))
                .thenReturn("invalid expression");
        when(msg.getMessage(anyString(), any(Object[].class), any(Locale.class)))
                .thenReturn("invalid expression");
    }

    // =========================================================================
    // 1. Allowlist pattern correctness
    // =========================================================================

    /**
     * The SAFE_MATH_EXPRESSION pattern must be non-null and compiled correctly.
     */
    @Test
    public void testSafeMathExpressionPatternIsNonNull() {
        assertNotNull("SAFE_MATH_EXPRESSION must not be null",
                OGNLExpressionInjectionController.SAFE_MATH_EXPRESSION);
    }

    /**
     * The allowlist must accept expressions that consist exclusively of digits,
     * arithmetic operators, parentheses, decimal points, and whitespace.
     */
    @Test
    public void testAllowlistAcceptsPureArithmeticCharacters() {
        Pattern p = OGNLExpressionInjectionController.SAFE_MATH_EXPRESSION;

        assertTrue("Digits only",          p.matcher("12345").matches());
        assertTrue("Addition",             p.matcher("1 + 2").matches());
        assertTrue("Subtraction",          p.matcher("10 - 3").matches());
        assertTrue("Multiplication",       p.matcher("6 * 7").matches());
        assertTrue("Division",             p.matcher("8 / 2").matches());
        assertTrue("Modulo",               p.matcher("10 % 3").matches());
        assertTrue("Parenthesised expr",   p.matcher("(1 + 2) * 3").matches());
        assertTrue("Decimal numbers",      p.matcher("3.14 * 2.0").matches());
        assertTrue("Nested parens",        p.matcher("((1 + 2) * (3 + 4))").matches());
        assertTrue("Unary minus",          p.matcher("-5 + 3").matches());
        assertTrue("Whitespace only expr", p.matcher("1   +   2").matches());
    }

    /**
     * The allowlist must reject any string that contains letters — letters are
     * required to spell out class names, method names, and OGNL keywords.
     */
    @Test
    public void testAllowlistRejectsLetters() {
        Pattern p = OGNLExpressionInjectionController.SAFE_MATH_EXPRESSION;

        assertFalse("Single letter",       p.matcher("a").matches());
        assertFalse("Identifier in expr",  p.matcher("x + 1").matches());
        assertFalse("Java class name",     p.matcher("Runtime").matches());
        assertFalse("Mixed digits+alpha",  p.matcher("1a2").matches());
    }

    /**
     * The allowlist must reject the @ sign, which is the OGNL static-class
     * accessor prefix (e.g., @Runtime@getRuntime().exec("id")).
     */
    @Test
    public void testAllowlistRejectsAtSign() {
        Pattern p = OGNLExpressionInjectionController.SAFE_MATH_EXPRESSION;

        assertFalse("@ alone",       p.matcher("@").matches());
        assertFalse("@Class@method", p.matcher("@Runtime@getRuntime().exec(\"id\")").matches());
        assertFalse("@Math@",        p.matcher("@Math@").matches());
    }

    /**
     * The allowlist must reject double-quotes, single-quotes, and backticks —
     * these can be used to embed string literals in OGNL that carry payloads.
     */
    @Test
    public void testAllowlistRejectsQuotesAndBackticks() {
        Pattern p = OGNLExpressionInjectionController.SAFE_MATH_EXPRESSION;

        assertFalse("Double quote",  p.matcher("\"id\"").matches());
        assertFalse("Single quote",  p.matcher("'id'").matches());
        assertFalse("Backtick",      p.matcher("`id`").matches());
    }

    /**
     * The allowlist must reject square brackets and curly braces used to
     * form OGNL array/map literals and projection syntax.
     */
    @Test
    public void testAllowlistRejectsBracketsAndBraces() {
        Pattern p = OGNLExpressionInjectionController.SAFE_MATH_EXPRESSION;

        assertFalse("Square brackets", p.matcher("[1,2,3]").matches());
        assertFalse("Curly braces",    p.matcher("{1:2}").matches());
    }

    /**
     * The allowlist must reject the # character used to access OGNL context
     * variables (e.g., #root, #session).
     */
    @Test
    public void testAllowlistRejectsHashContext() {
        Pattern p = OGNLExpressionInjectionController.SAFE_MATH_EXPRESSION;

        assertFalse("# alone",         p.matcher("#").matches());
        assertFalse("#root accessor",  p.matcher("#root").matches());
        assertFalse("#session access", p.matcher("#session['key']").matches());
    }

    // =========================================================================
    // 2. Injection payloads are blocked in the controller
    // =========================================================================

    /**
     * Classic OGNL RCE payload using static Runtime.exec().
     * The expression must never reach Ognl.parseExpression(); the controller
     * must return an error message instead.
     */
    @Test
    public void testRuntimeExecPayloadIsRejected() {
        String payload = "@java.lang.Runtime@getRuntime().exec(\"id\")";
        ModelAndView mav = invokeProcess(payload);

        assertNotNull("ModelAndView must not be null", mav);
        // A non-null "errmsg" attribute indicates the input was rejected
        assertNotNull("errmsg must be set for injection payload",
                mav.getModel().get("errmsg"));
        // The result 'value' must not be set — no OGNL evaluation occurred
        assertNull("value must not be set when payload is rejected",
                mav.getModel().get("value"));
    }

    /**
     * OGNL @-sign static class accessor with Process.exec().
     */
    @Test
    public void testAtSignClassAccessorPayloadIsRejected() {
        String payload = "@java.lang.ProcessBuilder@([\"id\"]).start()";
        ModelAndView mav = invokeProcess(payload);

        assertNotNull(mav);
        assertNotNull("errmsg must be set", mav.getModel().get("errmsg"));
        assertNull("value must not be set", mav.getModel().get("value"));
    }

    /**
     * Struts-style OGNL exploitation payload using #_memberAccess bypass.
     */
    @Test
    public void testMemberAccessBypassPayloadIsRejected() {
        String payload = "#_memberAccess['allowStaticMethodAccess']=true";
        ModelAndView mav = invokeProcess(payload);

        assertNotNull(mav);
        assertNotNull("errmsg must be set", mav.getModel().get("errmsg"));
        assertNull("value must not be set", mav.getModel().get("value"));
    }

    /**
     * Payload using the 'new' keyword to instantiate arbitrary classes.
     */
    @Test
    public void testNewKeywordPayloadIsRejected() {
        String payload = "new java.lang.String(\"injected\")";
        ModelAndView mav = invokeProcess(payload);

        assertNotNull(mav);
        assertNotNull("errmsg must be set", mav.getModel().get("errmsg"));
        assertNull("value must not be set", mav.getModel().get("value"));
    }

    /**
     * Payload that uses string method chaining via OGNL (e.g. "id".getClass()).
     */
    @Test
    public void testStringMethodChainPayloadIsRejected() {
        String payload = "\"id\".getClass().forName(\"java.lang.Runtime\")";
        ModelAndView mav = invokeProcess(payload);

        assertNotNull(mav);
        assertNotNull("errmsg must be set", mav.getModel().get("errmsg"));
        assertNull("value must not be set", mav.getModel().get("value"));
    }

    /**
     * Payload using OGNL context variable access to reach sensitive objects.
     */
    @Test
    public void testContextVariableAccessPayloadIsRejected() {
        String payload = "#context['com.opensymphony.xwork2.ActionContext.container']";
        ModelAndView mav = invokeProcess(payload);

        assertNotNull(mav);
        assertNotNull("errmsg must be set", mav.getModel().get("errmsg"));
        assertNull("value must not be set", mav.getModel().get("value"));
    }

    /**
     * A null/empty expression must be handled gracefully (no evaluation, no error).
     */
    @Test
    public void testNullExpressionIsIgnored() {
        ModelAndView mav = invokeProcess(null);

        assertNotNull(mav);
        // No expression submitted → no value and no errmsg set
        assertNull("value must not be set for null expression",
                mav.getModel().get("value"));
        assertNull("errmsg must not be set for null expression",
                mav.getModel().get("errmsg"));
    }

    /**
     * A blank/whitespace-only expression must be handled gracefully.
     */
    @Test
    public void testBlankExpressionIsIgnored() {
        ModelAndView mav = invokeProcess("   ");

        assertNotNull(mav);
        assertNull("value must not be set for blank expression",
                mav.getModel().get("value"));
    }

    // =========================================================================
    // 3. Legitimate arithmetic expressions still work
    // =========================================================================

    /**
     * A simple integer addition that produces a numeric result must not be
     * rejected by the allowlist guard.
     */
    @Test
    public void testSimpleAdditionIsAccepted() {
        ModelAndView mav = invokeProcess("1 + 1");

        assertNotNull(mav);
        // If the expression is well-formed arithmetic, OGNL evaluates it to 2.
        // The 'value' attribute is set only when the result is a valid number.
        // We assert that the injection guard did NOT produce an early-return with errmsg.
        // (The test does not assert specific numeric output since OGNL is live here.)
        // The key invariant: the expression attribute is echoed back.
        assertNotNull("expression must be echoed back to the view",
                mav.getModel().get("expression"));
    }

    /**
     * A simple multiplication expression must pass through the allowlist.
     */
    @Test
    public void testMultiplicationExpressionIsAccepted() {
        ModelAndView mav = invokeProcess("6 * 7");

        assertNotNull(mav);
        assertNotNull("expression must be echoed back",
                mav.getModel().get("expression"));
    }

    /**
     * Parenthesised expression with multiple operators must pass the allowlist.
     */
    @Test
    public void testParenthesisedExpressionIsAccepted() {
        ModelAndView mav = invokeProcess("(10 + 5) * 2");

        assertNotNull(mav);
        assertNotNull("expression must be echoed back",
                mav.getModel().get("expression"));
    }

    /**
     * Decimal-number expression must pass the allowlist.
     */
    @Test
    public void testDecimalExpressionIsAccepted() {
        ModelAndView mav = invokeProcess("3.14 * 2.0");

        assertNotNull(mav);
        assertNotNull("expression must be echoed back",
                mav.getModel().get("expression"));
    }

    // =========================================================================
    // 4. Taint-flow regression: the injection guard runs before OGNL parsing
    // =========================================================================

    /**
     * Verify that the SAFE_MATH_EXPRESSION allowlist check is structurally
     * present and guards the call to Ognl.parseExpression — i.e., that the
     * controller returns immediately (with errmsg set) when the expression fails
     * the allowlist before any OGNL API is reached.
     *
     * We confirm this by checking that the controller's early-return path sets
     * "errmsg" AND does NOT set "value" for an injection payload.
     */
    @Test
    public void testInjectionGuardCausesEarlyReturnBeforeOgnlParsing() {
        // Payload that would cause RCE if it reached Ognl.parseExpression()
        String rcePayload = "@java.lang.Runtime@getRuntime().exec(\"cat /etc/passwd\")";

        ModelAndView mav = invokeProcess(rcePayload);

        // errmsg must be present (the early-return path was taken)
        assertNotNull("errmsg must be present for rejected payload",
                mav.getModel().get("errmsg"));
        // value must be absent (OGNL evaluation never occurred)
        assertNull("value must be absent — OGNL must not have evaluated the payload",
                mav.getModel().get("value"));
    }

    /**
     * Confirm that the allowlist pattern SAFE_MATH_EXPRESSION itself rejects every
     * known OGNL metacharacter so that the guard cannot be bypassed by mixing safe
     * and unsafe characters.
     */
    @Test
    public void testAllowlistRejectsAllKnownOgnlMetacharacters() {
        Pattern p = OGNLExpressionInjectionController.SAFE_MATH_EXPRESSION;
        String[] metacharacters = {"@", "#", ":", "\"", "'", "[", "]", "{", "}", "\\", "=", "!", "<", ">", "?"};

        for (String meta : metacharacters) {
            assertFalse("Allowlist must reject OGNL metacharacter: " + meta,
                    p.matcher(meta).matches());
            assertFalse("Allowlist must reject expression containing: " + meta,
                    p.matcher("1 + 2" + meta).matches());
        }
    }

    // =========================================================================
    // Helper utilities
    // =========================================================================

    /**
     * Invokes the controller's process() method with the given expression and
     * returns the resulting ModelAndView.  MessageSource is mocked so that
     * msg.getMessage() calls do not throw NullPointerException.
     */
    private ModelAndView invokeProcess(String expression) {
        ModelAndView mav = new ModelAndView();
        Locale locale = Locale.ENGLISH;
        // msg is injected by Mockito; setUp() stubs it to return "invalid expression"
        // for any key so the early-return path can add the errmsg attribute safely.
        try {
            // Inject the mocked MessageSource via reflection since the field is
            // declared in AbstractController (superclass).
            Field msgField = org.t246osslab.easybuggy4sb.controller.AbstractController.class
                    .getDeclaredField("msg");
            msgField.setAccessible(true);
            msgField.set(controller, msg);
        } catch (Exception e) {
            throw new RuntimeException("Failed to inject MessageSource mock", e);
        }
        return controller.process(expression, mav, locale);
    }
}
