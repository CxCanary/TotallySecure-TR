package org.t246osslab.easybuggy4sb.vulnerabilities;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.util.Locale;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.MessageSource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.ModelAndView;

public class OGNLExpressionInjectionControllerTest {

    private final OGNLExpressionInjectionController controller = new OGNLExpressionInjectionController();

    @Before
    public void setUp() {
        MessageSource msg = mock(MessageSource.class);
        when(msg.getMessage(anyString(), any(), any(), any(Locale.class))).thenReturn("invalid");
        when(msg.getMessage(anyString(), any(), any(Locale.class))).thenReturn("msg");
        ReflectionTestUtils.setField(controller, "msg", msg);
    }

    private ModelAndView run(String expression) {
        return controller.process(expression, new ModelAndView(), Locale.ENGLISH);
    }

    @Test
    public void arithmeticIsEvaluated() {
        ModelAndView mav = run("1 + 2 * 3");
        assertEquals(7, ((Number) mav.getModel().get("value")).intValue());
        assertNull(mav.getModel().get("errmsg"));
    }

    @Test
    public void mathFunctionsAreEvaluated() {
        ModelAndView mav = run("Math.sqrt(Math.pow(2, 6)) - 5");
        assertEquals(3.0, ((Number) mav.getModel().get("value")).doubleValue(), 0.0001);
    }

    @Test
    public void mathConstantsAreEvaluated() {
        ModelAndView mav = run("Math.PI");
        assertEquals(Math.PI, ((Number) mav.getModel().get("value")).doubleValue(), 0.0001);
    }

    @Test
    public void injectedExpressionsAreNotExecuted() {
        File marker = new File(System.getProperty("java.io.tmpdir"), "ognl_injection_marker");
        marker.delete();
        String[] payloads = {
            "@java.lang.Runtime@getRuntime().exec('touch " + marker.getAbsolutePath() + "')",
            "T(java.lang.Runtime).getRuntime().exec('touch " + marker.getAbsolutePath() + "')",
            "new java.io.File('" + marker.getAbsolutePath() + "').createNewFile()",
            "(new java.lang.ProcessBuilder('touch','" + marker.getAbsolutePath() + "')).start()",
            "'a'.getClass().forName('java.lang.Runtime')",
            "Math.getClass()",
            "#root.getClass()"
        };
        for (String payload : payloads) {
            ModelAndView mav = run(payload);
            assertNull("Payload must not yield a value: " + payload, mav.getModel().get("value"));
            assertNotNull("Payload must be reported invalid: " + payload, mav.getModel().get("errmsg"));
        }
        assertFalse(marker.exists());
    }

    @Test
    public void blankExpressionYieldsNoValue() {
        ModelAndView mav = run("");
        assertNull(mav.getModel().get("value"));
        assertTrue(mav.getModel().containsKey("errmsg"));
    }
}
