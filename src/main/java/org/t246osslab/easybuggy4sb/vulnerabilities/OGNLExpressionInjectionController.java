package org.t246osslab.easybuggy4sb.vulnerabilities;

import java.lang.reflect.Method;
import java.util.Locale;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.springframework.expression.ExpressionException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.t246osslab.easybuggy4sb.Config;
import org.t246osslab.easybuggy4sb.controller.AbstractController;

@Controller
public class OGNLExpressionInjectionController extends AbstractController {

    /** Allowlisted one-argument java.lang.Math functions exposed to expressions. */
    private static final String[] MATH_FUNCTIONS_1ARG = { "sqrt", "cbrt", "abs", "sin", "cos", "tan", "asin", "acos",
            "atan", "exp", "log", "log10", "floor", "ceil", "rint", "signum", "toRadians", "toDegrees" };

    /** Allowlisted two-argument java.lang.Math functions exposed to expressions. */
    private static final String[] MATH_FUNCTIONS_2ARG = { "pow", "max", "min", "atan2", "hypot" };

    /**
     * Builds a restricted evaluation context. SimpleEvaluationContext has no type references, constructors, bean
     * references or method invocation, so only arithmetic and the allowlisted Math functions/constants (registered
     * as variables, referenced as #name) can be evaluated.
     */
    private static SimpleEvaluationContext createEvaluationContext() throws NoSuchMethodException {
        SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        for (String name : MATH_FUNCTIONS_1ARG) {
            ctx.setVariable(name, Math.class.getMethod(name, double.class));
        }
        for (String name : MATH_FUNCTIONS_2ARG) {
            Method m = Math.class.getMethod(name, double.class, double.class);
            ctx.setVariable(name, m);
        }
        ctx.setVariable("random", Math.class.getMethod("random"));
        ctx.setVariable("PI", Math.PI);
        ctx.setVariable("E", Math.E);
        return ctx;
    }

    @RequestMapping(value = Config.APP_ROOT + "/ognleijc")
    public ModelAndView process(@RequestParam(value = "expression", required = false) String expression,
            ModelAndView mav, Locale locale) {
        setViewAndCommonObjects(mav, locale, "commandinjection");
        Object value = null;
        String errMessage = "";
        if (!StringUtils.isBlank(expression)) {
            try {
                // "Math.xxx" in the user's expression is mapped to the allowlisted "#xxx" functions/constants
                value = new SpelExpressionParser().parseExpression(expression.replaceAll("Math\\.", "#"))
                        .getValue(createEvaluationContext());
            } catch (ExpressionException e) {
                errMessage = e.getSimpleMessage();
                log.debug("ExpressionException occurs: ", e);
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
