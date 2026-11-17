package net.hwyz.iov.cloud.sec.eiam.service.service;

import net.hwyz.iov.cloud.edd.mpt.api.constant.SecurityConstants;
import net.hwyz.iov.cloud.edd.mpt.api.domain.SysUser;
import net.hwyz.iov.cloud.edd.org.api.service.OrgEmployeeService;
import net.hwyz.iov.cloud.edd.org.api.vo.EmployeeChangeExService;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import net.hwyz.iov.cloud.sec.eiam.service.client.MptUserBindingClient;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamIdentityMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamSyncWatermarkMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamIdentityPo;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamSyncWatermarkPo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDate;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * SEC-EIAM-DSN-CR-002 / US-026：员工身份目录同步测试。
 * <p>
 * 覆盖：初始全量插入、已有记录更新、墓碑转 DELETED 并触发 MPT 停用、在职新员工触发自动开通、
 * 水位推进、ORG 返回 null 时不推进水位（抛错交由调度器退避重试）。
 *
 * @author hwyz_leo
 * @since 2026-11-17
 */
class IdentitySyncServiceTest {

    private EiamIdentityMapper identityMapper;
    private EiamSyncWatermarkMapper watermarkMapper;
    private OrgEmployeeService orgEmployeeService;
    private MptUserBindingClient mptUserBindingClient;
    private IdentitySyncService syncService;

    @BeforeEach
    void setUp() {
        identityMapper = mock(EiamIdentityMapper.class);
        watermarkMapper = mock(EiamSyncWatermarkMapper.class);
        orgEmployeeService = mock(OrgEmployeeService.class);
        mptUserBindingClient = mock(MptUserBindingClient.class);
        syncService = new IdentitySyncService();
        ReflectionTestUtils.setField(syncService, "identityMapper", identityMapper);
        ReflectionTestUtils.setField(syncService, "watermarkMapper", watermarkMapper);
        ReflectionTestUtils.setField(syncService, "orgEmployeeService", orgEmployeeService);
        ReflectionTestUtils.setField(syncService, "mptUserBindingClient", mptUserBindingClient);
        ReflectionTestUtils.setField(syncService, "enabled", true);
        ReflectionTestUtils.setField(syncService, "pageSize", 200);
        ReflectionTestUtils.setField(syncService, "provisionMpt", true);
    }

    @Test
    @DisplayName("首次同步：无水位全量拉取，插入目录并推进水位")
    void syncInsertsNewIdentity() {
        when(watermarkMapper.selectById("ORG")).thenReturn(null);
        when(orgEmployeeService.getEmployeeChanges(isNull(), eq(1), anyInt()))
                .thenReturn(new PageResult<>(List.of(change(1001L, true, true, null)), 1, 1, 200));
        when(identityMapper.selectOne(any())).thenReturn(null);
        when(mptUserBindingClient.provision(any(), eq(SecurityConstants.INNER)))
                .thenReturn(ApiResponse.ok(new SysUser()));

        int changes = syncService.syncOnce();

        assertEquals(1, changes);
        ArgumentCaptor<EiamIdentityPo> captor = ArgumentCaptor.forClass(EiamIdentityPo.class);
        verify(identityMapper).insert(captor.capture());
        EiamIdentityPo inserted = captor.getValue();
        assertEquals(1001L, inserted.getEmployeeId());
        assertEquals("E1001", inserted.getEmployeeCode());
        assertEquals(IdentitySyncService.STATUS_ACTIVE, inserted.getStatus());
        assertEquals(1, inserted.getEmployeeEnable());
        verify(watermarkMapper).insert(any(EiamSyncWatermarkPo.class));
        verify(mptUserBindingClient).provision(any(), eq(SecurityConstants.INNER));
    }

    @Test
    @DisplayName("已有员工更新：更新目录记录，状态 ACTIVE 不变时不重复开通")
    void syncUpdatesExistingIdentity() {
        when(watermarkMapper.selectById("ORG"))
                .thenReturn(EiamSyncWatermarkPo.builder().source("ORG").build());
        when(orgEmployeeService.getEmployeeChanges(any(), eq(1), anyInt()))
                .thenReturn(new PageResult<>(List.of(change(1001L, true, true, null)), 1, 1, 200));
        EiamIdentityPo existing = EiamIdentityPo.builder()
                .uid(1L).source("ORG").employeeId(1001L).status(IdentitySyncService.STATUS_ACTIVE).build();
        when(identityMapper.selectOne(any())).thenReturn(existing);

        syncService.syncOnce();

        verify(identityMapper).updateById(any(EiamIdentityPo.class));
        verify(identityMapper, never()).insert(any(EiamIdentityPo.class));
        verify(mptUserBindingClient, never()).provision(any(), any());
    }

    @Test
    @DisplayName("墓碑：rowValid=false 转 DELETED 并触发 MPT 停用")
    void syncTombstoneDisablesAccount() {
        when(watermarkMapper.selectById("ORG"))
                .thenReturn(EiamSyncWatermarkPo.builder().source("ORG").build());
        when(orgEmployeeService.getEmployeeChanges(any(), eq(1), anyInt()))
                .thenReturn(new PageResult<>(List.of(change(1001L, true, false, null)), 1, 1, 200));
        EiamIdentityPo existing = EiamIdentityPo.builder()
                .uid(1L).source("ORG").employeeId(1001L).status(IdentitySyncService.STATUS_ACTIVE).build();
        when(identityMapper.selectOne(any())).thenReturn(existing);

        syncService.syncOnce();

        ArgumentCaptor<EiamIdentityPo> captor = ArgumentCaptor.forClass(EiamIdentityPo.class);
        verify(identityMapper).updateById(captor.capture());
        assertEquals(IdentitySyncService.STATUS_DELETED, captor.getValue().getStatus());
        verify(mptUserBindingClient).disableByEmployeeId(eq(1001L), eq(SecurityConstants.INNER));
    }

    @Test
    @DisplayName("停用员工：状态 DISABLED 且不再触发开通")
    void syncDisabledEmployee() {
        when(watermarkMapper.selectById("ORG")).thenReturn(null);
        when(orgEmployeeService.getEmployeeChanges(isNull(), eq(1), anyInt()))
                .thenReturn(new PageResult<>(List.of(change(1002L, false, true, null)), 1, 1, 200));
        when(identityMapper.selectOne(any())).thenReturn(null);

        syncService.syncOnce();

        ArgumentCaptor<EiamIdentityPo> captor = ArgumentCaptor.forClass(EiamIdentityPo.class);
        verify(identityMapper).insert(captor.capture());
        assertEquals(IdentitySyncService.STATUS_DISABLED, captor.getValue().getStatus());
        verify(mptUserBindingClient, never()).provision(any(), any());
    }

    @Test
    @DisplayName("离职日期已到：状态 LEFT")
    void syncLeftEmployee() {
        when(watermarkMapper.selectById("ORG")).thenReturn(null);
        when(orgEmployeeService.getEmployeeChanges(isNull(), eq(1), anyInt()))
                .thenReturn(new PageResult<>(List.of(
                        change(1003L, true, true, LocalDate.now().minusDays(1))), 1, 1, 200));
        when(identityMapper.selectOne(any())).thenReturn(null);

        syncService.syncOnce();

        ArgumentCaptor<EiamIdentityPo> captor = ArgumentCaptor.forClass(EiamIdentityPo.class);
        verify(identityMapper).insert(captor.capture());
        assertEquals(IdentitySyncService.STATUS_LEFT, captor.getValue().getStatus());
    }

    @Test
    @DisplayName("ORG 不可用（返回 null）：抛错且不推进水位，交由调度器重试")
    void syncFailsWithoutAdvancingWatermark() {
        when(watermarkMapper.selectById("ORG")).thenReturn(null);
        when(orgEmployeeService.getEmployeeChanges(isNull(), eq(1), anyInt())).thenReturn(null);

        assertThrows(IllegalStateException.class, () -> syncService.syncOnce());
        verify(watermarkMapper, never()).insert(any(EiamSyncWatermarkPo.class));
    }

    @Test
    @DisplayName("同步停用开关关闭时直接跳过")
    void syncSkippedWhenDisabled() {
        ReflectionTestUtils.setField(syncService, "enabled", false);
        assertEquals(0, syncService.syncOnce());
        verify(orgEmployeeService, never()).getEmployeeChanges(anyLong(), anyInt(), anyInt());
    }

    private EmployeeChangeExService change(Long employeeId, boolean enable, boolean rowValid, LocalDate leaveDate) {
        return EmployeeChangeExService.builder()
                .employeeId(employeeId)
                .code("E" + employeeId)
                .name("员工" + employeeId)
                .phone("1390000" + employeeId)
                .enable(enable)
                .rowValid(rowValid)
                .leaveDate(leaveDate)
                .modifyTime(new Date(1763000000000L))
                .build();
    }
}
