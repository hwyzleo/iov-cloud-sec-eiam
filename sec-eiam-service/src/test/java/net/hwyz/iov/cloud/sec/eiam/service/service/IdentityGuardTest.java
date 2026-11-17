package net.hwyz.iov.cloud.sec.eiam.service.service;

import net.hwyz.iov.cloud.framework.common.exception.ServiceException;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamIdentityMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamIdentityPo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * SEC-EIAM-DSN-CR-002 / US-028：登录身份目录校验测试。
 * <p>
 * 覆盖：在职放行、停用/离职/删除拒绝、目录缺失拒绝、纯管理员（employeeId 为空）跳过。
 *
 * @author hwyz_leo
 * @since 2026-11-17
 */
class IdentityGuardTest {

    private EiamIdentityMapper identityMapper;
    private IdentityGuard identityGuard;

    @BeforeEach
    void setUp() {
        identityMapper = mock(EiamIdentityMapper.class);
        identityGuard = new IdentityGuard();
        ReflectionTestUtils.setField(identityGuard, "identityMapper", identityMapper);
        ReflectionTestUtils.setField(identityGuard, "checkEnabled", true);
    }

    @Test
    @DisplayName("在职员工允许登录")
    void activeEmployeeAllowed() {
        when(identityMapper.selectOne(any())).thenReturn(identity("ACTIVE", 1, null));
        assertDoesNotThrow(() -> identityGuard.assertLoginAllowed(1001L));
    }

    @Test
    @DisplayName("停用/离职/删除状态拒绝登录")
    void inactiveStatusRejected() {
        for (String status : new String[]{"DISABLED", "LEFT", "DELETED"}) {
            when(identityMapper.selectOne(any())).thenReturn(identity(status, 1, null));
            ServiceException ex = assertThrows(ServiceException.class, () -> identityGuard.assertLoginAllowed(1001L));
            assertTrue(ex.getMessage().contains("禁止登录"));
        }
    }

    @Test
    @DisplayName("ORG 启用标记为 0 时拒绝登录")
    void employeeDisabledRejected() {
        when(identityMapper.selectOne(any())).thenReturn(identity("ACTIVE", 0, null));
        assertThrows(ServiceException.class, () -> identityGuard.assertLoginAllowed(1001L));
    }

    @Test
    @DisplayName("离职日期已到拒绝登录，未到日期允许")
    void leaveDateChecked() {
        when(identityMapper.selectOne(any())).thenReturn(identity("ACTIVE", 1, LocalDate.now().minusDays(1)));
        assertThrows(ServiceException.class, () -> identityGuard.assertLoginAllowed(1001L));

        when(identityMapper.selectOne(any())).thenReturn(identity("ACTIVE", 1, LocalDate.now().plusDays(1)));
        assertDoesNotThrow(() -> identityGuard.assertLoginAllowed(1001L));
    }

    @Test
    @DisplayName("目录中不存在该员工时拒绝登录")
    void missingIdentityRejected() {
        when(identityMapper.selectOne(any())).thenReturn(null);
        assertThrows(ServiceException.class, () -> identityGuard.assertLoginAllowed(1001L));
    }

    @Test
    @DisplayName("纯管理员账号（未绑定员工）跳过目录校验")
    void adminWithoutEmployeeSkipped() {
        assertDoesNotThrow(() -> identityGuard.assertLoginAllowed(null));
    }

    @Test
    @DisplayName("紧急旁路：check-enabled=false 时跳过校验")
    void bypassWhenDisabled() {
        ReflectionTestUtils.setField(identityGuard, "checkEnabled", false);
        assertDoesNotThrow(() -> identityGuard.assertLoginAllowed(1001L));
    }

    private EiamIdentityPo identity(String status, Integer enable, LocalDate leaveDate) {
        return EiamIdentityPo.builder()
                .uid(1L)
                .source("ORG")
                .employeeId(1001L)
                .status(status)
                .employeeEnable(enable)
                .leaveDate(leaveDate)
                .build();
    }
}
