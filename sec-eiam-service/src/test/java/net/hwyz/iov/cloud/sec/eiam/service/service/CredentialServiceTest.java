package net.hwyz.iov.cloud.sec.eiam.service.service;

import com.baomidou.mybatisplus.core.conditions.Wrapper;
import net.hwyz.iov.cloud.edd.mpt.api.RemoteUserService;
import net.hwyz.iov.cloud.edd.mpt.api.domain.SysUser;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.exception.ServiceException;
import net.hwyz.iov.cloud.framework.security.util.SecurityUtils;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.exception.EiamBizException;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamCredentialMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamCredentialPo;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamIdentityPo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * EIAM 凭据校验/锁定/惰性迁移/重置/改密测试（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.11）。
 *
 * @author hwyz_leo
 * @since 2026-11-18
 */
class CredentialServiceTest {

    private static final String RAW_PASSWORD = "Passw0rd!2026";
    private static final Long UID = 11L;
    private static final Long EMPLOYEE_ID = 1001L;
    private static final String EMPLOYEE_CODE = "E1001";

    private EiamCredentialMapper credentialMapper;
    private RemoteUserService remoteUserService;
    private CredentialService credentialService;

    @BeforeEach
    void setUp() {
        credentialMapper = mock(EiamCredentialMapper.class);
        remoteUserService = mock(RemoteUserService.class);
        credentialService = new CredentialService();
        ReflectionTestUtils.setField(credentialService, "credentialMapper", credentialMapper);
        ReflectionTestUtils.setField(credentialService, "remoteUserService", remoteUserService);
        ReflectionTestUtils.setField(credentialService, "maxFailed", 5);
        ReflectionTestUtils.setField(credentialService, "lockMinutes", 15L);
        ReflectionTestUtils.setField(credentialService, "resetPasswordLength", 14);
        ReflectionTestUtils.setField(credentialService, "lazyMigrationEnabled", true);
    }

    @Test
    @DisplayName("凭据存在且密码正确：校验通过")
    void verifySuccess() {
        when(credentialMapper.selectById(UID)).thenReturn(credential(SecurityUtils.encryptPassword(RAW_PASSWORD), 0, 0, null));

        EiamCredentialPo result = credentialService.verify(identity(), RAW_PASSWORD);

        assertNotNull(result);
        assertEquals(UID, result.getUid());
    }

    @Test
    @DisplayName("密码错误：返回 401009 并累加失败次数")
    void verifyWrongPassword() {
        when(credentialMapper.selectById(UID)).thenReturn(credential(SecurityUtils.encryptPassword(RAW_PASSWORD), 0, 1, null));

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> credentialService.verify(identity(), "wrong-password"));

        assertEquals(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT, ex.getErrorCode());
        assertEquals("401009", ex.getErrorCode().getCode());
        // failed_count 由 1 更新为 2
        assertUpdatedValue(2);
    }

    @Test
    @DisplayName("连续错误达到阈值：锁定 15 分钟并返回 401010")
    void verifyLocksAtThreshold() {
        when(credentialMapper.selectById(UID)).thenReturn(credential(SecurityUtils.encryptPassword(RAW_PASSWORD), 0, 4, null));

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> credentialService.verify(identity(), "wrong-password"));

        assertEquals(EiamErrorCode.CREDENTIAL_ACCOUNT_LOCKED, ex.getErrorCode());
        assertTrue(ex.getMessage().contains("锁定"));
        assertUpdatedValue(5);
    }

    @Test
    @DisplayName("锁定期内即使密码正确也拒绝登录（不再校验密码）")
    void verifyRejectsLockedAccount() {
        when(credentialMapper.selectById(UID)).thenReturn(
                credential(SecurityUtils.encryptPassword(RAW_PASSWORD), 0, 5, LocalDateTime.now().plusMinutes(10)));

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> credentialService.verify(identity(), RAW_PASSWORD));

        assertEquals(EiamErrorCode.CREDENTIAL_ACCOUNT_LOCKED, ex.getErrorCode());
        verify(credentialMapper, never()).update(any(), any());
    }

    @Test
    @DisplayName("必须改密：密码正确也返回 401011，不返回通过结果")
    void verifyRequiresPasswordReset() {
        when(credentialMapper.selectById(UID)).thenReturn(
                credential(SecurityUtils.encryptPassword(RAW_PASSWORD), 1, 0, null));

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> credentialService.verify(identity(), RAW_PASSWORD));

        assertEquals(EiamErrorCode.CREDENTIAL_PWD_RESET_REQUIRED, ex.getErrorCode());
        assertEquals("401011", ex.getErrorCode().getCode());
    }

    @Test
    @DisplayName("惰性迁移：无凭据时用 MPT 密码校验一次并落库该哈希")
    void lazyMigrationWritesMptHash() {
        when(credentialMapper.selectById(UID)).thenReturn(null);
        String mptHash = SecurityUtils.encryptPassword(RAW_PASSWORD);
        when(remoteUserService.getUserInfo(eq(EMPLOYEE_CODE), anyString()))
                .thenReturn(ApiResponse.ok(mptLoginUser(mptHash, 0)));

        EiamCredentialPo result = credentialService.verify(identity(), RAW_PASSWORD);

        assertNotNull(result);
        ArgumentCaptor<EiamCredentialPo> captor = ArgumentCaptor.forClass(EiamCredentialPo.class);
        verify(credentialMapper).insert(captor.capture());
        assertEquals(UID, captor.getValue().getUid());
        // 落库的是 MPT 的原哈希（不重新加密），保证密码语义连续
        assertEquals(mptHash, captor.getValue().getPasswordHash());
        assertEquals(0, captor.getValue().getPwdResetRequired());
    }

    @Test
    @DisplayName("惰性迁移：MPT 密码错误返回 401009 且不落库")
    void lazyMigrationWrongPassword() {
        when(credentialMapper.selectById(UID)).thenReturn(null);
        when(remoteUserService.getUserInfo(eq(EMPLOYEE_CODE), anyString()))
                .thenReturn(ApiResponse.ok(mptLoginUser(SecurityUtils.encryptPassword(RAW_PASSWORD), 0)));

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> credentialService.verify(identity(), "other-password"));

        assertEquals(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT, ex.getErrorCode());
        verify(credentialMapper, never()).insert(any());
    }

    @Test
    @DisplayName("惰性迁移：MPT 账号未绑定该员工返回 401008")
    void lazyMigrationRejectsUnboundAccount() {
        when(credentialMapper.selectById(UID)).thenReturn(null);
        LoginUser other = mptLoginUser(SecurityUtils.encryptPassword(RAW_PASSWORD), 0);
        other.getSysUser().setEmployeeId(9999L);
        when(remoteUserService.getUserInfo(eq(EMPLOYEE_CODE), anyString())).thenReturn(ApiResponse.ok(other));

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> credentialService.verify(identity(), RAW_PASSWORD));

        assertEquals(EiamErrorCode.CREDENTIAL_NOT_FOUND, ex.getErrorCode());
        verify(credentialMapper, never()).insert(any());
    }

    @Test
    @DisplayName("惰性迁移：MPT 无该账号返回 401008")
    void lazyMigrationMissingMptUser() {
        when(credentialMapper.selectById(UID)).thenReturn(null);
        when(remoteUserService.getUserInfo(eq(EMPLOYEE_CODE), anyString()))
                .thenReturn(ApiResponse.fail("用户名或密码错误"));

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> credentialService.verify(identity(), RAW_PASSWORD));

        assertEquals(EiamErrorCode.CREDENTIAL_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    @DisplayName("惰性迁移：开关关闭时直接返回 401008")
    void lazyMigrationDisabled() {
        ReflectionTestUtils.setField(credentialService, "lazyMigrationEnabled", false);
        when(credentialMapper.selectById(UID)).thenReturn(null);

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> credentialService.verify(identity(), RAW_PASSWORD));

        assertEquals(EiamErrorCode.CREDENTIAL_NOT_FOUND, ex.getErrorCode());
        verify(remoteUserService, never()).getUserInfo(anyString(), anyString());
    }

    @Test
    @DisplayName("重置密码：一次性明文 12~16 位、BCrypt 可校验、标记必须改密并清锁定")
    void resetPassword() {
        when(credentialMapper.selectById(UID)).thenReturn(
                credential(SecurityUtils.encryptPassword("old-password"), 0, 5, LocalDateTime.now().plusMinutes(10)));

        String plain = credentialService.resetPassword(UID);

        assertNotNull(plain);
        assertTrue(plain.length() >= 12 && plain.length() <= 16, "重置密码长度必须为 12~16");
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Wrapper<EiamCredentialPo>> captor = ArgumentCaptor.forClass(Wrapper.class);
        verify(credentialMapper, atLeastOnce()).update(any(), captor.capture());
        Map<String, Object> values = paramValues(captor.getValue());
        assertTrue(values.values().stream().anyMatch(v -> v instanceof Integer && (Integer) v == 1),
                "必须置 pwd_reset_required=1");
        assertTrue(values.values().stream().anyMatch(v -> v == null), "必须清空 locked_until");
        assertTrue(values.values().stream().anyMatch(v -> v instanceof String s
                        && SecurityUtils.matchesPassword(plain, s)),
                "落库哈希必须能校验一次性明文");
    }

    @Test
    @DisplayName("重置密码：无凭据记录时插入新记录并标记必须改密")
    void resetPasswordCreatesCredential() {
        when(credentialMapper.selectById(UID)).thenReturn(null);

        String plain = credentialService.resetPassword(UID);

        ArgumentCaptor<EiamCredentialPo> captor = ArgumentCaptor.forClass(EiamCredentialPo.class);
        verify(credentialMapper).insert(captor.capture());
        assertEquals(1, captor.getValue().getPwdResetRequired());
        assertTrue(SecurityUtils.matchesPassword(plain, captor.getValue().getPasswordHash()));
    }

    @Test
    @DisplayName("自助改密：旧密码错误返回 401009；成功后清除必须改密标记")
    void changePassword() {
        String oldHash = SecurityUtils.encryptPassword(RAW_PASSWORD);
        when(credentialMapper.selectById(UID)).thenReturn(credential(oldHash, 1, 0, null));

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> credentialService.changePassword(UID, "bad-old", "new-password-1"));
        assertEquals(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT, ex.getErrorCode());

        credentialService.changePassword(UID, RAW_PASSWORD, "new-password-1");
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Wrapper<EiamCredentialPo>> captor = ArgumentCaptor.forClass(Wrapper.class);
        verify(credentialMapper, atLeastOnce()).update(any(), captor.capture());
        Map<String, Object> values = paramValues(captor.getValue());
        assertTrue(values.values().stream().anyMatch(v -> v instanceof String s
                && SecurityUtils.matchesPassword("new-password-1", s)));
        assertTrue(values.values().stream().anyMatch(v -> v instanceof Integer && (Integer) v == 0),
                "必须清除 pwd_reset_required");
    }

    @Test
    @DisplayName("自助改密：新密码长度非法时拒绝")
    void changePasswordRejectsShortPassword() {
        when(credentialMapper.selectById(UID))
                .thenReturn(credential(SecurityUtils.encryptPassword(RAW_PASSWORD), 1, 0, null));

        assertThrows(ServiceException.class, () -> credentialService.changePassword(UID, RAW_PASSWORD, "123"));
    }

    @Test
    @DisplayName("解锁：清空失败计数与锁定时间；isLocked/isEnabled 语义正确")
    void unlockAndStatusHelpers() {
        credentialService.unlock(UID);
        verify(credentialMapper).update(any(), any());

        assertTrue(credentialService.isLocked(credential(null, 0, 0, LocalDateTime.now().plusMinutes(1))));
        assertFalse(credentialService.isLocked(credential(null, 0, 0, LocalDateTime.now().minusMinutes(1))));
        assertTrue(credentialService.isEnabled(credential("hash", 0, 0, null)));
        assertFalse(credentialService.isEnabled(null));
    }

    // ---------- 支撑 ----------

    private EiamIdentityPo identity() {
        return EiamIdentityPo.builder()
                .uid(UID)
                .source("ORG")
                .employeeId(EMPLOYEE_ID)
                .employeeCode(EMPLOYEE_CODE)
                .status("ACTIVE")
                .employeeEnable(1)
                .build();
    }

    private EiamCredentialPo credential(String hash, int pwdResetRequired, int failedCount, LocalDateTime lockedUntil) {
        return EiamCredentialPo.builder()
                .uid(UID)
                .passwordHash(hash)
                .pwdResetRequired(pwdResetRequired)
                .failedCount(failedCount)
                .lockedUntil(lockedUntil)
                .build();
    }

    private LoginUser mptLoginUser(String passwordHash, Integer pwdResetRequired) {
        SysUser sysUser = new SysUser();
        sysUser.setUserId(1L);
        sysUser.setUserName(EMPLOYEE_CODE);
        sysUser.setEmployeeId(EMPLOYEE_ID);
        sysUser.setPassword(passwordHash);
        sysUser.setPwdResetRequired(pwdResetRequired);
        LoginUser loginUser = new LoginUser();
        loginUser.setSysUser(sysUser);
        loginUser.setEmployeeId(EMPLOYEE_ID);
        return loginUser;
    }

    private Map<String, Object> paramValues(Wrapper<EiamCredentialPo> wrapper) {
        return ((com.baomidou.mybatisplus.core.conditions.AbstractWrapper<?, ?, ?>) wrapper)
                .getParamNameValuePairs();
    }

    private void assertUpdatedValue(int expectedFailedCount) {
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Wrapper<EiamCredentialPo>> captor = ArgumentCaptor.forClass(Wrapper.class);
        verify(credentialMapper, atLeastOnce()).update(any(), captor.capture());
        List<Object> values = paramValues(captor.getValue()).values().stream()
                .map(v -> (Object) v)
                .toList();
        assertTrue(values.stream().anyMatch(v -> v instanceof Number n && n.intValue() == expectedFailedCount),
                "期望 failed_count=" + expectedFailedCount + "，实际参数=" + values);
    }
}
