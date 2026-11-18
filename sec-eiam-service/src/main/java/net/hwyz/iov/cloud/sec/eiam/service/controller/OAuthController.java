package net.hwyz.iov.cloud.sec.eiam.service.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.exception.ServiceException;
import net.hwyz.iov.cloud.framework.security.util.SecurityUtils;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.exception.EiamBizException;
import net.hwyz.iov.cloud.sec.eiam.service.oauth.AuthorizationCodeStore;
import net.hwyz.iov.cloud.sec.eiam.service.oauth.OAuthClientValidator;
import net.hwyz.iov.cloud.sec.eiam.service.oauth.OAuthService;
import net.hwyz.iov.cloud.sec.eiam.service.service.EiamSsoLoginService;
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
 * OIDC 授权码端点（SEC-EIAM-DSN-CR-002 / US-027，原地修订·第二次）
 * <p>
 * 与既有 `/login`（MPT 后台账密登录）并存：两者最终都由本服务签发同一个平台令牌。
 * 授权端点要求已有登录会话；未登录时 302 到 EIAM 内置登录页（只校验 EIAM 自有凭据）。
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
    private EiamSsoLoginService eiamSsoLoginService;

    /**
     * EIAM 单点登录页（最小实现：由本服务承载，只校验 EIAM 凭据）
     */
    @GetMapping("/login")
    public void loginPage(@RequestParam String client_id,
                          @RequestParam String redirect_uri,
                          @RequestParam(required = false) String state,
                          HttpServletResponse response) throws IOException {
        if (!validateClient(client_id, redirect_uri, response)) {
            return;
        }
        renderLoginPage(response, client_id, redirect_uri, state, "", null, false);
    }

    /**
     * EIAM 单点登录表单提交：EIAM 凭据校验 → 目录校验 → MPT 装配账号与权限 → 一次性授权码
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
        LoginUser loginUser;
        try {
            loginUser = eiamSsoLoginService.authenticate(username, password);
        } catch (EiamBizException e) {
            boolean needChangePassword = EiamErrorCode.CREDENTIAL_PWD_RESET_REQUIRED == e.getErrorCode();
            renderLoginPage(response, client_id, redirect_uri, state, username, e.getMessage(), needChangePassword);
            return;
        } catch (ServiceException e) {
            renderLoginPage(response, client_id, redirect_uri, state, username, e.getMessage(), false);
            return;
        }
        Long employeeId = loginUser.getEmployeeId();
        if (employeeId == null) {
            renderLoginPage(response, client_id, redirect_uri, state, username,
                    "该账号未绑定员工，无法使用单点登录，请联系管理员", false);
            return;
        }
        redirectWithCode(employeeId, client_id, redirect_uri, state, response);
    }

    /**
     * 强制首登改密 / 自助改密：校验旧密码后更新为新密码，成功后直接完成单点登录
     */
    @PostMapping("/password")
    public void changePassword(@RequestParam String username,
                               @RequestParam String oldPassword,
                               @RequestParam String newPassword,
                               @RequestParam String client_id,
                               @RequestParam String redirect_uri,
                               @RequestParam(required = false) String state,
                               HttpServletResponse response) throws IOException {
        if (!validateClient(client_id, redirect_uri, response)) {
            return;
        }
        LoginUser loginUser;
        try {
            loginUser = eiamSsoLoginService.changePasswordAndLoad(username, oldPassword, newPassword);
        } catch (EiamBizException e) {
            renderLoginPage(response, client_id, redirect_uri, state, username,
                    e.getMessage(), true);
            return;
        } catch (ServiceException e) {
            renderLoginPage(response, client_id, redirect_uri, state, username,
                    e.getMessage(), true);
            return;
        }
        redirectWithCode(loginUser.getEmployeeId(), client_id, redirect_uri, state, response);
    }

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
            // 未登录：跳转 EIAM 内置登录页（只校验 EIAM 凭据）
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
     * 生成一次性授权码并 302 回跳客户端
     */
    private void redirectWithCode(Long employeeId, String clientId, String redirectUri, String state,
                                  HttpServletResponse response) throws IOException {
        String code = authorizationCodeStore.issue(clientId, employeeId, redirectUri);
        String location = redirectUri + (redirectUri.contains("?") ? "&" : "?") + "code=" + code
                + (state == null ? "" : "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8));
        response.sendRedirect(location);
    }

    /**
     * 渲染 EIAM 登录页（含错误提示与可选的改密表单）
     * <p>
     * 表单 `action=""`（提交到当前地址）与相对 `action="password"` 均按浏览器当前外部前缀解析，
     * 兼容网关 `/prod-api/auth` 前缀而不需对外暴露 EIAM 端口。
     */
    private void renderLoginPage(HttpServletResponse response, String clientId, String redirectUri,
                                 String state, String username, String errorMessage,
                                 boolean showChangePassword) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"/>")
                .append("<title>EIAM 单点登录</title><style>body{font-family:sans-serif;background:#f5f7fa;display:flex;")
                .append("align-items:center;justify-content:center;min-height:100vh;margin:0}.card{background:#fff;padding:32px;")
                .append("border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.1);width:340px}h3{margin:0 0 16px;text-align:center}")
                .append("input{width:100%;padding:10px;margin-bottom:14px;border:1px solid #dcdfe6;border-radius:4px;box-sizing:border-box}")
                .append("button{width:100%;padding:10px;background:#409eff;color:#fff;border:0;border-radius:4px;cursor:pointer}")
                .append(".err{background:#fef0f0;color:#f56c6c;padding:8px;border-radius:4px;margin-bottom:14px;font-size:13px}")
                .append(".tip{color:#909399;font-size:12px;margin-top:12px;line-height:1.5}")
                .append(".sec{margin-top:18px;border-top:1px dashed #dcdfe6;padding-top:16px}")
                .append("</style></head><body><div>")
                .append("<form class=\"card\" method=\"post\" action=\"\">")
                .append("<h3>EIAM 单点登录</h3>");
        if (errorMessage != null && !errorMessage.isBlank()) {
            html.append("<div class=\"err\">").append(escape(errorMessage)).append("</div>");
        }
        html.append("<input name=\"username\" value=\"").append(escape(username == null ? "" : username))
                .append("\" placeholder=\"工号\" autocomplete=\"off\"/>")
                .append("<input name=\"password\" type=\"password\" placeholder=\"EIAM 登录密码\" autocomplete=\"off\"/>")
                .append(hidden("client_id", clientId))
                .append(hidden("redirect_uri", redirectUri))
                .append(hidden("state", state == null ? "" : state))
                .append("<button type=\"submit\">登 录</button>")
                .append("<div class=\"tip\">使用 EIAM 身份凭据登录（与 MPT 后台密码彼此独立）</div>")
                .append("</form>");
        if (showChangePassword) {
            html.append("<form class=\"card sec\" method=\"post\" action=\"password\">")
                    .append("<h3>设置新密码</h3>")
                    .append(hidden("username", username == null ? "" : username))
                    .append("<input name=\"oldPassword\" type=\"password\" placeholder=\"当前密码（重置后的临时密码）\" autocomplete=\"off\"/>")
                    .append("<input name=\"newPassword\" type=\"password\" placeholder=\"新密码（5~20 位）\" autocomplete=\"off\"/>")
                    .append(hidden("client_id", clientId))
                    .append(hidden("redirect_uri", redirectUri))
                    .append(hidden("state", state == null ? "" : state))
                    .append("<button type=\"submit\">修改密码并登录</button>")
                    .append("</form>");
        }
        html.append("</div></body></html>");
        response.getWriter().write(html.toString());
    }

    private String hidden(String name, String value) {
        return "<input type=\"hidden\" name=\"" + name + "\" value=\"" + escape(value) + "\"/>";
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
