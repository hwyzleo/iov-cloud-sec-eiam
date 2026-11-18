package net.hwyz.iov.cloud.sec.eiam.service.service;

import net.hwyz.iov.cloud.edd.mpt.api.domain.SysUser;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.sec.eiam.service.client.MptUserBindingClient;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.exception.EiamBizException;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamIdentityMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamCredentialPo;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamIdentityPo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * EIAM 单点登录凭据认证测试（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.5）。
 *
 * @author hwyz_leo
 * @since 2026-11-18
 */
class EiamSsoLoginServiceTest {

    private EiamIdentityMapper identityMapper;
    private CredentialService credentialService;
    private IdentityGuard identityGuard;
    private MptUserBindingClient mptUserBindingClient;
    private SysRecordLogService recordLogService;
    private EiamSsoLoginService eiamSsoLoginService;

    @BeforeEach
    void setUp() {
        identityMapper = mock(EiamIdentityMapper.class);
        credentialService = mock(CredentialService.class);
        identityGuard = mock(IdentityGuard.class);
        mptUserBindingClient = mock(MptUserBindingClient.class);
        recordLogService = mock(SysRecordLogService.class);
        eiamSsoLoginService = new EiamSsoLoginService();
        ReflectionTestUtils.setField(eiamSsoLoginService, "identityMapper", identityMapper);
        ReflectionTestUtils.setField(eiamSsoLoginService, "credentialService", credentialService);
        ReflectionTestUtils.setField(eiamSsoLoginService, "identityGuard", identityGuard);
        ReflectionTestUtils.setField(eiamSsoLoginService, "mptUserBindingClient", mptUserBindingClient);
        ReflectionTestUtils.setField(eiamSsoLoginService, "recordLogService", recordLogService);
    }

    @Test
    @DisplayName("EIAM 凭据通过后按 employeeId 装配 MPT 账号与权限")
    void authenticateSuccess() {
        when(identityMapper.selectOne(any())).thenReturn(identity());
        when(credentialService.verify(any(), eq("pwd"))).thenReturn(EiamCredentialPo.builder().uid(11L).build());
        when(mptUserBindingClient.getUserByEmployeeId(eq(1001L), anyString())).thenReturn(ApiResponse.ok(loginUser()));

        LoginUser loginUser = eiamSsoLoginService.authenticate("E1001", "pwd");

        assertNotNull(loginUser);
        assertEquals(1001L, loginUser.getEmployeeId());
        assertEquals("zhangsan", loginUser.getSysUser().getUserName());
        verify(identityGuard).assertLoginAllowed(1001L);
    }

    @Test
    @DisplayName("目录中不存在该工号：返回 401005，且不校验凭据")
    void authenticateIdentityMissing() {
        when(identityMapper.selectOne(any())).thenReturn(null);

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> eiamSsoLoginService.authenticate("E404", "pwd"));

        assertEquals(EiamErrorCode.IDENTITY_NOT_FOUND, ex.getErrorCode());
        verify(credentialService, never()).verify(any(), anyString());
    }

    @Test
    @DisplayName("必须改密：401011 直接向上抛出，不调用 MPT 装配（不签发 token）")
    void authenticateRequiresPasswordReset() {
        when(identityMapper.selectOne(any())).thenReturn(identity());
        when(credentialService.verify(any(), anyString()))
                .thenThrow(new EiamBizException(EiamErrorCode.CREDENTIAL_PWD_RESET_REQUIRED));

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> eiamSsoLoginService.authenticate("E1001", "pwd"));

        assertEquals(EiamErrorCode.CREDENTIAL_PWD_RESET_REQUIRED, ex.getErrorCode());
        verify(mptUserBindingClient, never()).getUserByEmployeeId(anyLong(), anyString());
    }

    @Test
    @DisplayName("目录禁止登录：401006 向上抛出")
    void authenticateInactiveIdentity() {
        when(identityMapper.selectOne(any())).thenReturn(identity());
        doThrow(new EiamBizException(EiamErrorCode.IDENTITY_NOT_ACTIVE))
                .when(identityGuard).assertLoginAllowed(1001L);

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> eiamSsoLoginService.authenticate("E1001", "pwd"));

        assertEquals(EiamErrorCode.IDENTITY_NOT_ACTIVE, ex.getErrorCode());
    }

    @Test
    @DisplayName("MPT 未绑定账号：401007；MPT 账号停用：401006")
    void authenticateMptErrors() {
        when(identityMapper.selectOne(any())).thenReturn(identity());
        when(credentialService.verify(any(), anyString())).thenReturn(EiamCredentialPo.builder().uid(11L).build());

        when(mptUserBindingClient.getUserByEmployeeId(anyLong(), anyString()))
                .thenReturn(ApiResponse.<LoginUser>builder().code("100101").message("该员工尚未绑定账号").build());
        EiamBizException missing = assertThrows(EiamBizException.class,
                () -> eiamSsoLoginService.authenticate("E1001", "pwd"));
        assertEquals(EiamErrorCode.MPT_USER_BINDING_MISSING, missing.getErrorCode());

        when(mptUserBindingClient.getUserByEmployeeId(anyLong(), anyString()))
                .thenReturn(ApiResponse.<LoginUser>builder().code("100103").message("账号已停用或已删除").build());
        EiamBizException disabled = assertThrows(EiamBizException.class,
                () -> eiamSsoLoginService.authenticate("E1001", "pwd"));
        assertEquals(EiamErrorCode.IDENTITY_NOT_ACTIVE, disabled.getErrorCode());
    }

    @Test
    @DisplayName("改密后直接完成登录：委托凭据服务更新密码并装配账号")
    void changePasswordAndLoad() {
        when(identityMapper.selectOne(any())).thenReturn(identity());
        when(mptUserBindingClient.getUserByEmployeeId(eq(1001L), anyString())).thenReturn(ApiResponse.ok(loginUser()));

        LoginUser loginUser = eiamSsoLoginService.changePasswordAndLoad("E1001", "old-pwd", "new-pwd-123");

        assertEquals(1001L, loginUser.getEmployeeId());
        verify(credentialService).changePassword(11L, "old-pwd", "new-pwd-123");
    }

    @Test
    @DisplayName("登录审计写入失败（MPT 日志不可用）不影响登录结果")
    void auditFailureDoesNotBreakLogin() {
        when(identityMapper.selectOne(any())).thenReturn(identity());
        when(credentialService.verify(any(), anyString())).thenReturn(EiamCredentialPo.builder().uid(11L).build());
        when(mptUserBindingClient.getUserByEmployeeId(eq(1001L), anyString())).thenReturn(ApiResponse.ok(loginUser()));
        org.mockito.Mockito.doThrow(new RuntimeException("MPT log down"))
                .when(recordLogService).recordLogininfor(anyString(), anyString(), anyString());

        LoginUser loginUser = eiamSsoLoginService.authenticate("E1001", "pwd");

        assertNotNull(loginUser);
        assertEquals(1001L, loginUser.getEmployeeId());
    }

    private EiamIdentityPo identity() {
        return EiamIdentityPo.builder()
                .uid(11L)
                .source("ORG")
                .employeeId(1001L)
                .employeeCode("E1001")
                .displayName("张三")
                .status("ACTIVE")
                .employeeEnable(1)
                .build();
    }

    private LoginUser loginUser() {
        SysUser sysUser = new SysUser();
        sysUser.setUserId(1L);
        sysUser.setUserName("zhangsan");
        sysUser.setEmployeeId(1001L);
        LoginUser loginUser = new LoginUser();
        loginUser.setSysUser(sysUser);
        loginUser.setEmployeeId(1001L);
        return loginUser;
    }
}
