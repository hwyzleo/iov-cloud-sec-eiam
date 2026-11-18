package net.hwyz.iov.cloud.sec.eiam.service.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import net.hwyz.iov.cloud.sec.eiam.service.client.MptUserBindingClient;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.exception.EiamBizException;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamIdentityMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamCredentialPo;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamIdentityPo;
import net.hwyz.iov.cloud.sec.eiam.service.vo.IdentityView;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 身份目录管理测试（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.7）。
 *
 * @author hwyz_leo
 * @since 2026-11-18
 */
class IdentityAdminServiceTest {

    private EiamIdentityMapper identityMapper;
    private CredentialService credentialService;
    private MptUserBindingClient mptUserBindingClient;
    private IdentityAdminService identityAdminService;

    @BeforeEach
    void setUp() {
        identityMapper = mock(EiamIdentityMapper.class);
        credentialService = mock(CredentialService.class);
        mptUserBindingClient = mock(MptUserBindingClient.class);
        identityAdminService = new IdentityAdminService();
        ReflectionTestUtils.setField(identityAdminService, "identityMapper", identityMapper);
        ReflectionTestUtils.setField(identityAdminService, "credentialService", credentialService);
        ReflectionTestUtils.setField(identityAdminService, "mptUserBindingClient", mptUserBindingClient);
    }

    @Test
    @DisplayName("目录分页：返回凭据状态与是否须改密/锁定，且不含哈希")
    void listMapsCredentialState() {
        EiamIdentityPo identity = identity(11L, 1001L, "E1001");
        Page<EiamIdentityPo> page = new Page<>(1, 10);
        page.setRecords(List.of(identity));
        page.setTotal(1);
        when(identityMapper.selectPage(ArgumentMatchers.<Page<EiamIdentityPo>>any(), any())).thenReturn(page);
        when(credentialService.findByUids(any())).thenReturn(Map.of(11L,
                EiamCredentialPo.builder().uid(11L).passwordHash("hash").pwdResetRequired(1)
                        .failedCount(5).lockedUntil(LocalDateTime.now().plusMinutes(5)).build()));
        when(credentialService.isEnabled(any())).thenCallRealMethod();
        when(credentialService.isLocked(any())).thenCallRealMethod();

        PageResult<IdentityView> result = identityAdminService.list(null, null, 1, 10);

        assertEquals(1, result.getItems().size());
        IdentityView view = result.getItems().get(0);
        assertEquals(1001L, view.getEmployeeId());
        assertEquals("E1001", view.getEmployeeCode());
        assertTrue(view.isCredentialEnabled());
        assertTrue(view.isPwdResetRequired());
        assertTrue(view.isLocked());
    }

    @Test
    @DisplayName("目录分页：未开通凭据时 credentialEnabled=false")
    void listWithoutCredential() {
        Page<EiamIdentityPo> page = new Page<>(1, 10);
        page.setRecords(List.of(identity(11L, 1001L, "E1001")));
        page.setTotal(1);
        when(identityMapper.selectPage(ArgumentMatchers.<Page<EiamIdentityPo>>any(), any())).thenReturn(page);
        when(credentialService.findByUids(any())).thenReturn(Map.of());
        when(credentialService.isEnabled(any())).thenCallRealMethod();
        when(credentialService.isLocked(any())).thenCallRealMethod();

        IdentityView view = identityAdminService.list("E1", "ACTIVE", 1, 10).getItems().get(0);

        assertFalse(view.isCredentialEnabled());
        assertFalse(view.isPwdResetRequired());
        assertFalse(view.isLocked());
    }

    @Test
    @DisplayName("重置密码：按员工定位身份后委托凭据服务，返回一次性明文")
    void resetPassword() {
        when(identityMapper.selectOne(any())).thenReturn(identity(11L, 1001L, "E1001"));
        when(credentialService.resetPassword(11L)).thenReturn("Abcdef23456789");

        assertEquals("Abcdef23456789", identityAdminService.resetPassword(1001L));
        verify(credentialService).resetPassword(11L);
    }

    @Test
    @DisplayName("启用：清凭据锁定并联动 MPT 启用账号")
    void enable() {
        when(identityMapper.selectOne(any())).thenReturn(identity(11L, 1001L, "E1001"));
        when(mptUserBindingClient.enableByEmployeeId(eq(1001L), anyString())).thenReturn(ApiResponse.ok(1));

        assertEquals(1, identityAdminService.enable(1001L));
        verify(credentialService).unlock(11L);
    }

    @Test
    @DisplayName("停用：联动 MPT 停用账号")
    void disable() {
        when(identityMapper.selectOne(any())).thenReturn(identity(11L, 1001L, "E1001"));
        when(mptUserBindingClient.disableByEmployeeId(eq(1001L), anyString())).thenReturn(ApiResponse.ok(1));

        assertEquals(1, identityAdminService.disable(1001L));
        verify(credentialService, never()).unlock(anyLong());
    }

    @Test
    @DisplayName("MPT 联动失败：抛出带业务码的异常")
    void enableMptFailure() {
        when(identityMapper.selectOne(any())).thenReturn(identity(11L, 1001L, "E1001"));
        when(mptUserBindingClient.enableByEmployeeId(eq(1001L), anyString()))
                .thenReturn(ApiResponse.fail("账号已删除"));

        EiamBizException ex = assertThrows(EiamBizException.class, () -> identityAdminService.enable(1001L));
        assertEquals(EiamErrorCode.MPT_USER_BINDING_MISSING, ex.getErrorCode());
    }

    @Test
    @DisplayName("目录中不存在该员工：返回 401005")
    void identityMissing() {
        when(identityMapper.selectOne(any())).thenReturn(null);

        EiamBizException ex = assertThrows(EiamBizException.class,
                () -> identityAdminService.resetPassword(9999L));
        assertEquals(EiamErrorCode.IDENTITY_NOT_FOUND, ex.getErrorCode());
    }

    @Test
    @DisplayName("解锁：委托凭据服务清空锁定")
    void unlock() {
        when(identityMapper.selectOne(any())).thenReturn(identity(11L, 1001L, "E1001"));

        identityAdminService.unlock(1001L);

        verify(credentialService).unlock(11L);
    }

    private EiamIdentityPo identity(Long uid, Long employeeId, String employeeCode) {
        return EiamIdentityPo.builder()
                .uid(uid)
                .source("ORG")
                .employeeId(employeeId)
                .employeeCode(employeeCode)
                .displayName("张三")
                .phone("13800000000")
                .status("ACTIVE")
                .employeeEnable(1)
                .orgModifyTime(LocalDateTime.now())
                .syncTime(LocalDateTime.now())
                .build();
    }
}
