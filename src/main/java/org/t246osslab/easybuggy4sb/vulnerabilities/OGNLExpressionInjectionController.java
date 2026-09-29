package org.t246osslab.easybuggy4sb.vulnerabilities;

import java.lang.reflect.Member;
import java.lang.reflect.Modifier;
import java.util.Locale;
import java.util.Map;

import ognl.AbstractMemberAccess;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.t246osslab.easybuggy4sb.Config;
import org.t246osslab.easybuggy4sb.controller.AbstractController;

import ognl.Ognl;
import ognl.OgnlContext;
import ognl.OgnlException;

@Controller
public class OGNLExpressionInjectionController extends AbstractController {

    /**
     * Allowlist of permitted characters for a safe arithmetic expression.
     * Only digits, basic arithmetic operators (+, -, *, /, %), parentheses,
     * decimal points, and whitespace are allowed.  Any expression containing
     * letters, @-signs, quotes, brackets, or other characters that would allow
     * OGNL constructs (class references, method calls, static access, etc.) is
     * rejected before reaching the OGNL engine, breaking the taint flow
     * described in CWE-917.
     */
    static final java.util.regex.Pattern SAFE_MATH_EXPRESSION =
            java.util.regex.Pattern.compile("^[0-9+\\-*/%().\\s]+$");

    @RequestMapping(value = Config.APP_ROOT + "/ognleijc")
    public ModelAndView process(@RequestParam(value = "expression", required = false) String expression,
            ModelAndView mav, Locale locale) {
        setViewAndCommonObjects(mav, locale, "commandinjection");
        Object value = null;
        String errMessage = "";
        OgnlContext ctx = new OgnlContext(null, null, (new AbstractMemberAccess() {
            public boolean isAccessible(Map context, Object target, Member member, String propertyName) {
                int modifiers = member.getModifiers();// 228
                return Modifier.isPublic(modifiers);// 229
            }
        }));
        if (!StringUtils.isBlank(expression)) {
            // Security fix (CWE-917): only pass the expression to OGNL when it matches
            // the strict arithmetic allowlist.  Expressions that contain letters, class
            // references (@…@), method calls, or any other non-arithmetic characters are
            // rejected here — the tainted string never reaches Ognl.parseExpression().
            if (!SAFE_MATH_EXPRESSION.matcher(expression).matches()) {
                mav.addObject("expression", expression);
                mav.addObject("errmsg",
                        msg.getMessage("msg.invalid.expression", new String[] { errMessage }, null, locale));
                return mav;
            }
            try {
                Object expr = Ognl.parseExpression(expression);
                value = Ognl.getValue(expr, ctx);
            } catch (OgnlException e) {
                if (e.getReason() != null) {
                    errMessage = e.getReason().getMessage();
                }
                log.debug("OgnlException occurs: ", e);
            } catch (Exception e) {
                log.debug("Exception occurs: ", e);
            } catch (Error e) {
                log.debug("Error occurs: ", e);
            }
        }
        if (expression != null) {
            mav.addObject("expression", expression);
            if (value == null) {
                mav.addObject("errmsg",
                        msg.getMessage("msg.invalid.expression", new String[] { errMessage }, null, locale));
            }
        }
        if (value != null && NumberUtils.isNumber(value.toString())) {
            mav.addObject("value", value);
        }
        return mav;
    }
}
