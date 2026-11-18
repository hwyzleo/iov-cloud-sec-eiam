package net.hwyz.iov.cloud.sec.eiam.service.controller;

import net.hwyz.iov.cloud.edd.mpt.api.domain.SysUser;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.exception.EiamBizException;
import net.hwyz.iov.cloud.sec.eiam.service.oauth.AuthorizationCodeStore;
import net.hwyz.iov.cloud.sec.eiam.service.oauth.OAuthClientValidator;
import net.hwyz.iov.cloud.sec.eiam.service.service.EiamSsoLoginService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * EIAM 登录页与改密页测试（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.5 / §13.6）。
 * <p>
 * 覆盖：只校验 EIAM 凭据、401011 不签发授权码、锁定文案、相对 action、改密成功后直接回跳。
 *
 * @author hwyz_leo
 * @since 2026-11-18
 */
class OAuthLoginPageTest {

    private static final String CLIENT_ID = "mpt";
    private static final String REDIRECT_URI = "http://admin.example.com/sso/callback";
    private static final String STATE = "state-123";

    private OAuthClientValidator clientValidator;
    private AuthorizationCodeStore authorizationCodeStore;
    private EiamSsoLoginService eiamSsoLoginService;
    private OAuthController controller;

    @BeforeEach
    void setUp() {
        clientValidator = mock(OAuthClientValidator.class);
        authorizationCodeStore = mock(AuthorizationCodeStore.class);
        eiamSsoLoginService = mock(EiamSsoLoginService.class);
        controller = new OAuthController();
        ReflectionTestUtils.setField(controller, "clientValidator", clientValidator);
        ReflectionTestUtils.setField(controller, "authorizationCodeStore", authorizationCodeStore);
        ReflectionTestUtils.setField(controller, "eiamSsoLoginService", eiamSsoLoginService);
    }

    @Test
    @DisplayName("登录页：表单提交到当前地址（action 为空），不含 MPT 密码文案")
    void loginPageUsesRelativeAction() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        controller.loginPage(CLIENT_ID, REDIRECT_URI, STATE, response);

        String html = response.getContentAsString();
        assertTrue(html.contains("action=\"\""));
        assertTrue(html.contains("name=\"client_id\" value=\"mpt\""));
        assertTrue(html.contains("EIAM 登录密码"));
    }

    @Test
    @DisplayName("EIAM 凭据通过：签发一次性授权码并 302 回跳（携带 state）")
    void loginIssuesCode() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(eiamSsoLoginService.authenticate("E1001", "pwd")).thenReturn(loginUser());
        when(authorizationCodeStore.issue(CLIENT_ID, 1001L, REDIRECT_URI)).thenReturn("CODE123");

        controller.doLogin("E1001", "pwd", CLIENT_ID, REDIRECT_URI, STATE, response);

        assertEquals(302, response.getStatus());
        String location = response.getHeader("Location");
        assertTrue(location.startsWith(REDIRECT_URI + "?code=CODE123"), location);
        assertTrue(location.contains("state=" + STATE), location);
    }

    @Test
    @DisplayName("必须改密（401011）：不签发授权码，渲染改密表单")
    void loginRequiresPasswordChange() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(eiamSsoLoginService.authenticate(anyString(), anyString()))
                .thenThrow(new EiamBizException(EiamErrorCode.CREDENTIAL_PWD_RESET_REQUIRED));

        controller.doLogin("E1001", "pwd", CLIENT_ID, REDIRECT_URI, STATE, response);

        assertNull(response.getHeader("Location"));
        String html = response.getContentAsString();
        assertTrue(html.contains("设置新密码"));
        assertTrue(html.contains("action=\"password\""));
        assertTrue(html.contains(EiamErrorCode.CREDENTIAL_PWD_RESET_REQUIRED.getMessage()));
        verify(authorizationCodeStore, never()).issue(anyString(), any(), anyString());
    }

    @Test
    @DisplayName("账号锁定（401010）：回显锁定文案，不跳转")
    void loginLocked() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(eiamSsoLoginService.authenticate(anyString(), anyString()))
                .thenThrow(new EiamBizException(EiamErrorCode.CREDENTIAL_ACCOUNT_LOCKED));

        controller.doLogin("E1001", "pwd", CLIENT_ID, REDIRECT_URI, STATE, response);

        assertNull(response.getHeader("Location"));
        assertTrue(response.getContentAsString().contains("锁定"));
    }

    @Test
    @DisplayName("密码错误（401009）：回显错误且不签发授权码")
    void loginWrongPassword() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(eiamSsoLoginService.authenticate(anyString(), anyString()))
                .thenThrow(new EiamBizException(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT));

        controller.doLogin("E1001", "pwd", CLIENT_ID, REDIRECT_URI, STATE, response);

        assertNull(response.getHeader("Location"));
        assertTrue(response.getContentAsString().contains("工号或密码错误"));
        assertFalse(response.getContentAsString().contains("设置新密码"));
    }

    @Test
    @DisplayName("改密成功：直接签发授权码并回跳，无需再次输入密码")
    void changePasswordIssuesCode() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(eiamSsoLoginService.changePasswordAndLoad("E1001", "temp", "new-pwd-123")).thenReturn(loginUser());
        when(authorizationCodeStore.issue(CLIENT_ID, 1001L, REDIRECT_URI)).thenReturn("CODE456");

        controller.changePassword("E1001", "temp", "new-pwd-123", CLIENT_ID, REDIRECT_URI, STATE, response);

        assertEquals(302, response.getStatus());
        assertTrue(response.getHeader("Location").contains("code=CODE456"));
        verify(eiamSsoLoginService).changePasswordAndLoad(eq("E1001"), eq("temp"), eq("new-pwd-123"));
    }

    @Test
    @DisplayName("改密失败（旧密码错误）：保留改密表单并提示")
    void changePasswordFailure() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(eiamSsoLoginService.changePasswordAndLoad(anyString(), anyString(), anyString()))
                .thenThrow(new EiamBizException(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT));

        controller.changePassword("E1001", "bad", "new-pwd-123", CLIENT_ID, REDIRECT_URI, STATE, response);

        assertNull(response.getHeader("Location"));
        assertTrue(response.getContentAsString().contains("设置新密码"));
        verify(authorizationCodeStore, never()).issue(anyString(), any(), anyString());
    }

    private LoginUser loginUser() {
        SysUser sysUser = new SysUser();
        sysUser.setUserId(1L);
        sysUser.setUserName("zhangsan");
        LoginUser loginUser = new LoginUser();
        loginUser.setSysUser(sysUser);
        loginUser.setEmployeeId(1001L);
        return loginUser;
    }
}
