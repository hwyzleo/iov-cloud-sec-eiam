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

    @Autowired
    private net.hwyz.iov.cloud.sec.eiam.service.service.SysLoginService sysLoginService;

    /**
     * 登录页相对路径（相对当前请求目录 `/oauth2/`），保证在网关外部前缀（如 `/prod-api/auth`）下同样可达
     */
    private static final String LOGIN_PATH = "/oauth2/login";

    /**
     * 授权端点：校验客户端与回调，生成一次性授权码并回跳
     */
    @GetMapping("/authorize")
    public void authorize(@RequestParam String client_id,
                          @RequestParam String redirect_uri,
                          @RequestParam(required = false) String state,
                          HttpServletResponse response) throws IOException {
        if (!validateClient(client_id, redirect_uri, response)) {
            return;
        }

        LoginUser loginUser = SecurityUtils.getLoginUser();
        if (loginUser == null) {
            // 未登录：跳转 EIAM 内置登录页（凭据仍由 MPT 校验）
            // 相对地址：浏览器按当前外部路径（如 /prod-api/auth/oauth2/authorize）解析为同名前缀下的登录页，
            // 因此无需对外暴露 EIAM 独立端口。
            String loginUrl = "login?client_id=" + URLEncoder.encode(client_id, StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(redirect_uri, StandardCharsets.UTF_8)
                    + (state == null ? "" : "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8));
            // 手写 302：相对 Location 由浏览器按外部 URL（含 /prod-api/auth 前缀）解析；
            // sendRedirect 会基于容器内部路径生成绝对地址，导致丢失网关前缀。
            response.setStatus(HttpServletResponse.SC_FOUND);
            response.setHeader("Location", loginUrl);
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

    /**
     * EIAM 单点登录页（最小实现：由本服务承载，凭据仍由 MPT 校验）
     */
    @GetMapping("/login")
    public void loginPage(@RequestParam String client_id,
                          @RequestParam String redirect_uri,
                          @RequestParam(required = false) String state,
                          HttpServletResponse response) throws IOException {
        if (!validateClient(client_id, redirect_uri, response)) {
            return;
        }
        response.setContentType("text/html;charset=UTF-8");
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"/>")
            .append("<title>EIAM 单点登录</title><style>body{font-family:sans-serif;background:#f5f7fa;display:flex;")
            .append("align-items:center;justify-content:center;height:100vh;margin:0}.card{background:#fff;padding:32px;")
            .append("border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.1);width:320px}h3{margin:0 0 20px;text-align:center}")
            .append("input{width:100%;padding:10px;margin-bottom:14px;border:1px solid #dcdfe6;border-radius:4px;box-sizing:border-box}")
            .append("button{width:100%;padding:10px;background:#409eff;color:#fff;border:0;border-radius:4px;cursor:pointer}")
            .append("</style></head><body><form class=\"card\" method=\"post\" action=\"\">")
            .append("<h3>EIAM 单点登录</h3>")
            .append("<input name=\"username\" placeholder=\"工号/账号\" autocomplete=\"off\"/>")
            .append("<input name=\"password\" type=\"password\" placeholder=\"密码\" autocomplete=\"off\"/>")
            .append("<input type=\"hidden\" name=\"client_id\" value=\"").append(escape(client_id)).append("\"/>")
            .append("<input type=\"hidden\" name=\"redirect_uri\" value=\"").append(escape(redirect_uri)).append("\"/>")
            .append("<input type=\"hidden\" name=\"state\" value=\"").append(escape(state == null ? "" : state)).append("\"/>")
            .append("<button type=\"submit\">登 录</button></form></body></html>");
        response.getWriter().write(html.toString());
    }

    /**
     * EIAM 单点登录表单提交：校验凭据后生成一次性授权码并回跳客户端
     */
    @PostMapping("/login")
    public void doLogin(@RequestParam String username,
                        @RequestParam String password,
                        @RequestParam String client_id,
                        @RequestParam String redirect_uri,
                        @RequestParam(required = false) String state,
                        HttpServletResponse response) throws IOException {
        if (!validateClient(client_id, redirect_uri, response)) {
            return;
        }
        LoginUser loginUser = sysLoginService.login(username, password);
        Long employeeId = loginUser.getEmployeeId();
        if (employeeId == null) {
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write("<html><body style=\"font-family:sans-serif\">该账号未绑定员工，无法使用单点登录，请联系管理员。</body></html>");
            return;
        }
        String code = authorizationCodeStore.issue(client_id, employeeId, redirect_uri);
        String location = redirect_uri + (redirect_uri.contains("?") ? "&" : "?") + "code=" + code
                + (state == null ? "" : "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8));
        response.sendRedirect(location);
    }

    /**
     * 校验客户端与回调地址；失败时直接输出结构化错误（不冒泡为 500）
     */
    private boolean validateClient(String clientId, String redirectUri, HttpServletResponse response) throws IOException {
        try {
            clientValidator.validate(clientId, redirectUri);
            return true;
        } catch (ServiceException e) {
            EiamErrorCode errorCode = e.getMessage() != null && e.getMessage().contains("回调地址")
                    ? EiamErrorCode.SSO_REDIRECT_URI_INVALID
                    : EiamErrorCode.SSO_CLIENT_INVALID;
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":\"" + errorCode.getCode()
                    + "\",\"message\":\"" + errorCode.getMessage() + "\"}");
            return false;
        }
    }

    private String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
