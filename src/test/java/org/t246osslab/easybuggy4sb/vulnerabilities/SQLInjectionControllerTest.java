package org.t246osslab.easybuggy4sb.vulnerabilities;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
import java.util.Locale;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.MessageSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.ModelAndView;
import org.t246osslab.easybuggy4sb.core.model.User;

public class SQLInjectionControllerTest {

    private static final String EXPECTED_SQL = "SELECT name, secret from USERS where name=? or password=?";

    private final SQLInjectionController controller = new SQLInjectionController();
    private JdbcTemplate jdbcTemplate;

    @Before
    public void setUp() {
        MessageSource msg = mock(MessageSource.class);
        when(msg.getMessage(anyString(), any(), any(Locale.class))).thenReturn("msg");
        jdbcTemplate = mock(JdbcTemplate.class);
        ReflectionTestUtils.setField(controller, "msg", msg);
        ReflectionTestUtils.setField(controller, "jdbcTemplate", jdbcTemplate);
    }

    private ModelAndView post(String name, String password) {
        return controller.process(name, password, new ModelAndView(), new MockHttpServletRequest("POST", "/sqlijc"),
                Locale.ENGLISH);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void inputIsBoundAsParametersNotConcatenated() {
        User user = new User();
        user.setName("admin");
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), any(Object[].class)))
                .thenReturn(Collections.singletonList(user));

        ModelAndView mav = post("admin", "password123");

        verify(jdbcTemplate).query(eq(EXPECTED_SQL), any(RowMapper.class), eq("admin"), eq("password123"));
        assertEquals(1, ((List<?>) mav.getModel().get("userList")).size());
        assertNull(mav.getModel().get("errmsg"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void injectionPayloadIsPassedAsDataOnly() {
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), any(Object[].class)))
                .thenReturn(Collections.emptyList());
        String namePayload = "admin' --";
        String passwordPayload = "' OR '1'='1";

        ModelAndView mav = post(namePayload, passwordPayload);

        // The SQL text must stay constant; payloads may only appear as bound arguments.
        verify(jdbcTemplate).query(eq(EXPECTED_SQL), any(RowMapper.class), eq(namePayload), eq(passwordPayload));
        assertNotNull(mav.getModel().get("errmsg"));
        assertNull(mav.getModel().get("userList"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void shortPasswordDoesNotReachDatabase() {
        post("admin", "short");
        verify(jdbcTemplate, never()).query(anyString(), any(RowMapper.class), any(Object[].class));
    }
}
