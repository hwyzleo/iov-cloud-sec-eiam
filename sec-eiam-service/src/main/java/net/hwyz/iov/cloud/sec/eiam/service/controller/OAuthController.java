package net.hwyz.iov.cloud.sec.eiam.service.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.exception.ServiceException;
import net.hwyz.iov.cloud.framework.security.util.SecurityUtils;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.oauth.AuthorizationCodeStore;
import net.hwyz.iov.cloud.sec.eiam.service.oauth.OAuthClientValidator;
import net.hwyz.iov.cloud.sec.eiam.service.oauth.OAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * OIDC 授权码端点（SEC-EIAM-DSN-CR-002 / US-027）
 * <p>
 * 与既有 `/login`（账密登录）并存：两者最终都由本服务签发同一个平台令牌。
 * 授权端点要求已有登录会话；未登录时返回 401 语义错误，由前端先完成登录再发起单点登录。
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequestMapping("/oauth2")
public class OAuthController {

    @Autowired
    private OAuthClientValidator clientValidator;

    @Autowired
    private AuthorizationCodeStore authorizationCodeStore;

    @Autowired
    private OAuthService oauthService;

    /**
     * 授权端点：校验客户端与回调，生成一次性授权码并回跳
     */
    @GetMapping("/authorize")
    public void authorize(@RequestParam String client_id,
                          @RequestParam String redirect_uri,
                          @RequestParam(required = false) String state,
                          HttpServletResponse response) throws IOException {
        clientValidator.validate(client_id, redirect_uri);

        LoginUser loginUser = SecurityUtils.getLoginUser();
        if (loginUser == null) {
            // 未登录：不生成授权码，要求前端先完成登录（/auth/login）
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":\"401005\",\"message\":\"未登录，请先通过账密登录后再发起单点登录\"}");
            return;
        }
        Long employeeId = loginUser.getEmployeeId();
        if (employeeId == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":\"" + EiamErrorCode.IDENTITY_NOT_FOUND.getCode()
                    + "\",\"message\":\"" + EiamErrorCode.IDENTITY_NOT_FOUND.getMessage() + "\"}");
            return;
        }

        String code = authorizationCodeStore.issue(client_id, employeeId, redirect_uri);
        String location = redirect_uri + (redirect_uri.contains("?") ? "&" : "?") + "code=" + code
                + (state == null ? "" : "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8));
        log.info("单点登录授权：clientId={}, employeeId={}", client_id, employeeId);
        response.sendRedirect(location);
    }

    /**
     * 令牌端点：授权码换取平台令牌
     */
    @PostMapping("/token")
    public ApiResponse<Map<String, Object>> token(@RequestParam String code,
                                                  @RequestParam String client_id,
                                                  @RequestParam String redirect_uri,
                                                  @RequestParam(required = false, defaultValue = "authorization_code") String grant_type) {
        if (!"authorization_code".equals(grant_type)) {
            throw new ServiceException(EiamErrorCode.SSO_CODE_INVALID.getMessage());
        }
        return ApiResponse.ok(oauthService.exchange(code, client_id, redirect_uri));
    }
}
