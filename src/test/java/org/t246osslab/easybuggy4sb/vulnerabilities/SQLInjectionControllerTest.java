package org.t246osslab.easybuggy4sb.vulnerabilities;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Locale;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.MessageSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.ModelAndView;

public class SQLInjectionControllerTest {

    private static final String EXPECTED_SQL = "SELECT name, secret from USERS where name=? or password=?";

    private SQLInjectionController controller;
    private JdbcTemplate jdbcTemplate;

    @Before
    public void setUp() {
        controller = new SQLInjectionController();
        jdbcTemplate = mock(JdbcTemplate.class);
        MessageSource messageSource = mock(MessageSource.class);
        when(messageSource.getMessage(anyString(), any(), any(Locale.class))).thenReturn("message");
        ReflectionTestUtils.setField(controller, "jdbcTemplate", jdbcTemplate);
        ReflectionTestUtils.setField(controller, "msg", messageSource);
        // an unstubbed Mockito mock returns an empty List, which the controller treats as "user not found"
    }

    @Test
    public void inputsAreBoundAsParametersNotConcatenated() {
        String name = "admin";
        String password = "password123";

        controller.process(name, password, new ModelAndView(), new MockHttpServletRequest("POST", "/"),
                Locale.ENGLISH);

        verify(jdbcTemplate).query(eq(EXPECTED_SQL), any(RowMapper.class), eq(name), eq(password));
    }

    @Test
    public void injectionPayloadsNeverReachSqlText() {
        String[] payloads = { "' or '1'='1", "x' or 1=1 --", "'; DROP TABLE USERS; --", "' union select name, secret from USERS --" };
        for (String payload : payloads) {
            String password = payload + "        "; // ensure min length of 8 after trim handling
            controller.process(payload, password, new ModelAndView(),
                    new MockHttpServletRequest("POST", "/"), Locale.ENGLISH);
        }

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object> argCaptor = ArgumentCaptor.forClass(Object.class);
        verify(jdbcTemplate, org.mockito.Mockito.times(payloads.length)).query(sqlCaptor.capture(),
                any(RowMapper.class), argCaptor.capture(), argCaptor.capture());

        for (String sql : sqlCaptor.getAllValues()) {
            assertEquals(EXPECTED_SQL, sql);
            assertFalse(sql.contains("'"));
        }
        // payloads are passed through verbatim as bind values
        assertTrue(argCaptor.getAllValues().contains(payloads[0]));
        // the non-parameterized query overload must not be used
        verify(jdbcTemplate, never()).query(anyString(), any(RowMapper.class));
    }
}
