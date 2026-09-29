package org.t246osslab.easybuggy4sb.vulnerabilities;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.t246osslab.easybuggy4sb.core.model.User;

/**
 * Tests that SQLInjectionController uses parameterized queries and is not
 * vulnerable to SQL injection via the 'name' or 'password' parameters.
 *
 * The key security assertion is that JdbcTemplate.query is called with
 * Object[] bind parameters — never with a dynamically concatenated SQL string.
 */
@RunWith(MockitoJUnitRunner.class)
public class SQLInjectionControllerTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    @InjectMocks
    private SQLInjectionController controller;

    private User mockUser;

    @Before
    public void setUp() {
        mockUser = new User();
        mockUser.setName("alice");
        mockUser.setSecret("topsecret");
    }

    // -------------------------------------------------------------------------
    // Helper: stub jdbcTemplate.query(sql, Object[], RowMapper) to return a list
    // -------------------------------------------------------------------------
    @SuppressWarnings("unchecked")
    private void stubQueryToReturn(List<User> users) {
        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
                .thenReturn(users);
    }

    // =========================================================================
    // 1. Parameterized query structure
    // =========================================================================

    /**
     * Verifies that the SQL template passed to JdbcTemplate uses '?' placeholders
     * and does NOT contain any user-supplied data embedded in the string.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSelectUsersUsesParameterizedQuery_notStringConcatenation() {
        String maliciousName = "' OR '1'='1";
        String maliciousPassword = "' OR '1'='1' --";

        stubQueryToReturn(Collections.emptyList());

        // Capture the SQL string and parameters actually passed to JdbcTemplate
        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> paramsCaptor = ArgumentCaptor.forClass(Object[].class);

        // Invoke via reflection to reach private selectUsers through the controller's
        // process() path; we exercise it by calling the JdbcTemplate mock directly
        // through a real call stub instead.
        when(jdbcTemplate.query(sqlCaptor.capture(), paramsCaptor.capture(), any(RowMapper.class)))
                .thenReturn(Collections.emptyList());

        // Trigger via reflection since selectUsers is private — we call it indirectly
        // through mockMvc-style invocation is not set up here; instead we verify the
        // JdbcTemplate contract via the captured arguments.
        invokeSelectUsers(maliciousName, maliciousPassword);

        String capturedSql = sqlCaptor.getValue();
        Object[] capturedParams = paramsCaptor.getValue();

        // The SQL must contain '?' placeholders (parameterized)
        assert capturedSql.contains("?") : "SQL must use '?' placeholders for parameters";

        // The SQL must NOT contain the raw malicious input
        assert !capturedSql.contains(maliciousName)
                : "SQL must not embed raw user input (SQL injection risk)";
        assert !capturedSql.contains(maliciousPassword)
                : "SQL must not embed raw user input (SQL injection risk)";

        // The user input must be passed as bind parameters, not baked into the string
        assert capturedParams != null && capturedParams.length == 2
                : "Exactly 2 bind parameters expected";
        assert maliciousName.equals(capturedParams[0])
                : "First bind param must be the name value";
        assert maliciousPassword.equals(capturedParams[1])
                : "Second bind param must be the password value";
    }

    /**
     * Verifies that the fixed SQL template is a constant with exactly two
     * '?' placeholders and does not embed any runtime data.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSqlTemplateIsConstantWithTwoPlaceholders() {
        stubQueryToReturn(Collections.emptyList());

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        when(jdbcTemplate.query(sqlCaptor.capture(), any(Object[].class), any(RowMapper.class)))
                .thenReturn(Collections.emptyList());

        invokeSelectUsers("normalUser", "normalPassword12345");

        String sql = sqlCaptor.getValue();
        // Count '?' occurrences: must be exactly 2 (one for name, one for password)
        int placeholderCount = sql.length() - sql.replace("?", "").length();
        assert placeholderCount == 2 : "Expected exactly 2 '?' placeholders, found: " + placeholderCount;
    }

    // =========================================================================
    // 2. SQL injection attack payloads are treated as literal data
    // =========================================================================

    /**
     * Classic tautology injection: 'admin' OR '1'='1' -- should NOT bypass the query
     * by being embedded in the SQL. The payload must only appear in the parameters array.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testTautologyInjectionPayloadNotEmbeddedInSql() {
        String payload = "admin' OR '1'='1' --";

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> paramsCaptor = ArgumentCaptor.forClass(Object[].class);

        when(jdbcTemplate.query(sqlCaptor.capture(), paramsCaptor.capture(), any(RowMapper.class)))
                .thenReturn(Collections.emptyList());

        invokeSelectUsers(payload, "somepassword12345");

        // Payload must NOT be in the SQL string
        assert !sqlCaptor.getValue().contains(payload)
                : "SQL injection payload must not be embedded in the SQL string";
        // Payload must be in the bind parameters
        assert payload.equals(paramsCaptor.getValue()[0])
                : "Payload must be passed as a bind parameter, not baked into SQL";
    }

    /**
     * UNION-based injection to read all table data should not alter SQL structure.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testUnionBasedInjectionPayloadNotEmbeddedInSql() {
        String payload = "' UNION SELECT name, secret FROM USERS --";

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Object[]> paramsCaptor = ArgumentCaptor.forClass(Object[].class);

        when(jdbcTemplate.query(sqlCaptor.capture(), paramsCaptor.capture(), any(RowMapper.class)))
                .thenReturn(Collections.emptyList());

        invokeSelectUsers(payload, "password12345678");

        assert !sqlCaptor.getValue().toUpperCase().contains("UNION")
                : "UNION keyword must not appear in the parameterized SQL template";
        assert payload.equals(paramsCaptor.getValue()[0])
                : "UNION payload must be a literal bind parameter";
    }

    /**
     * DROP TABLE injection should not reach the SQL as executable SQL syntax.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testDropTableInjectionPayloadNotEmbeddedInSql() {
        String payload = "'; DROP TABLE USERS; --";

        ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);

        when(jdbcTemplate.query(sqlCaptor.capture(), any(Object[].class), any(RowMapper.class)))
                .thenReturn(Collections.emptyList());

        invokeSelectUsers(payload, "password12345678");

        assert !sqlCaptor.getValue().contains("DROP")
                : "DROP statement must not be embedded in the SQL template";
    }

    // =========================================================================
    // 3. Normal operation: legitimate credentials still work
    // =========================================================================

    /**
     * A valid user should be returned when the database lookup matches.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testLegitimateUserLookupReturnsResults() {
        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
                .thenReturn(Arrays.asList(mockUser));

        List<User> result = invokeSelectUsers("alice", "correctpassword");

        assert result != null && !result.isEmpty() : "Expected a non-empty result for a matching user";
        assert "alice".equals(result.get(0).getName()) : "Returned user name should be 'alice'";
    }

    /**
     * A non-existent user should yield an empty result, not an exception.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testNonExistentUserReturnsEmptyList() {
        when(jdbcTemplate.query(anyString(), any(Object[].class), any(RowMapper.class)))
                .thenReturn(Collections.emptyList());

        List<User> result = invokeSelectUsers("unknownUser", "password12345678");

        assert result != null && result.isEmpty() : "Expected empty result for unknown user";
    }

    // =========================================================================
    // 4. Regression: the vulnerable overload (String sql only) is not used
    // =========================================================================

    /**
     * The single-argument jdbcTemplate.query(String, RowMapper) overload (which does
     * NOT accept bind parameters) must never be called — it would indicate
     * a regression to the concatenated-SQL pattern.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testVulnerableQueryOverloadIsNeverCalled() {
        stubQueryToReturn(Collections.emptyList());

        invokeSelectUsers("anyuser", "anypassword12345");

        // query(String, RowMapper) — no bind parameters — must never be called
        verify(jdbcTemplate, never()).query(anyString(), any(RowMapper.class));
    }

    // =========================================================================
    // Helper: invoke the private selectUsers method via reflection
    // =========================================================================

    @SuppressWarnings("unchecked")
    private List<User> invokeSelectUsers(String name, String password) {
        try {
            java.lang.reflect.Method method =
                    SQLInjectionController.class.getDeclaredMethod("selectUsers", String.class, String.class);
            method.setAccessible(true);
            return (List<User>) method.invoke(controller, name, password);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            }
            throw new RuntimeException("Unexpected checked exception", e.getCause());
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke selectUsers via reflection", e);
        }
    }
}
