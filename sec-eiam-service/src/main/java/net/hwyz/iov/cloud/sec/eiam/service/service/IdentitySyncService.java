package net.hwyz.iov.cloud.sec.eiam.service.service;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

/**
 * 员工身份目录同步（SEC-EIAM-DSN-CR-002 / US-026）
 * <p>
 * 按 ORG `modify_time` 水位增量拉取员工变更（含墓碑），幂等 upsert 到 `eiam_identity`；
 * 任意一页失败则不推进水位，交由调度器退避重试。新员工（ACTIVE 且未绑定）自动在 MPT 开通账号，
 * 不可登录的员工触发 MPT 停用。
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
public class IdentitySyncService {

    /**
     * 身份来源
     */
    public static final String SOURCE_ORG = "ORG";

    /**
     * 状态常量
     */
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_DISABLED = "DISABLED";
    public static final String STATUS_LEFT = "LEFT";
    public static final String STATUS_DELETED = "DELETED";

    /**
     * MPT 内部契约错误码
     */
    private static final String MPT_USER_NAME_CONFLICT = "100102";

    @Autowired
    private EiamIdentityMapper identityMapper;

    @Autowired
    private EiamSyncWatermarkMapper watermarkMapper;

    @Autowired
    private OrgEmployeeService orgEmployeeService;

    @Autowired
    private MptUserBindingClient mptUserBindingClient;

    @Value("${eiam.sync.enabled:true}")
    private boolean enabled;

    @Value("${eiam.sync.page-size:200}")
    private int pageSize;

    @Value("${eiam.sync.provision-mpt:true}")
    private boolean provisionMpt;

    /**
     * 执行一轮同步
     *
     * @return 本轮处理的变更条数
     */
    public int syncOnce() {
        if (!enabled) {
            log.debug("员工目录同步已停用（eiam.sync.enabled=false）");
            return 0;
        }
        EiamSyncWatermarkPo watermark = loadWatermark();
        LocalDateTime since = watermark == null ? null : watermark.getWatermark();
        int page = 1;
        int total = 0;
        LocalDateTime lastModify = since;
        while (true) {
            PageResult<EmployeeChangeExService> result = orgEmployeeService.getEmployeeChanges(toEpochMilli(since), page, pageSize);
            if (result == null) {
                throw new IllegalStateException("ORG 员工增量接口不可用（返回 null）");
            }
            List<EmployeeChangeExService> items = result.getItems();
            if (CollectionUtils.isEmpty(items)) {
                break;
            }
            for (EmployeeChangeExService item : items) {
                applyChange(item);
                LocalDateTime modifyTime = toLocalDateTime(item.getModifyTime());
                if (modifyTime != null && (lastModify == null || modifyTime.isAfter(lastModify))) {
                    lastModify = modifyTime;
                }
            }
            total += items.size();
            // 水位仅在全部页处理成功后统一保存：中途失败不推进水位，保证不漏数据
            if (items.size() < effectivePageSize()) {
                break;
            }
            since = lastModify;
            page++;
        }
        saveWatermark(lastModify, "SUCCESS", total + " changes");
        return total;
    }

    /**
     * 应用单条员工变更
     *
     * @param change ORG 变更项
     */
    void applyChange(EmployeeChangeExService change) {
        if (change == null || change.getEmployeeId() == null) {
            return;
        }
        EiamIdentityPo existing = identityMapper.selectOne(Wrappers.<EiamIdentityPo>lambdaQuery()
                .eq(EiamIdentityPo::getSource, SOURCE_ORG)
                .eq(EiamIdentityPo::getEmployeeId, change.getEmployeeId())
                .last("limit 1"));
        String targetStatus = resolveStatus(change);
        // 变更前状态需在覆盖前捕获（既开通/停用的触发条件依赖它）
        String previousStatus = existing == null ? null : existing.getStatus();
        EiamIdentityPo identity = existing == null ? new EiamIdentityPo() : existing;
        identity.setSource(SOURCE_ORG);
        identity.setEmployeeId(change.getEmployeeId());
        identity.setEmployeeCode(change.getCode());
        identity.setDisplayName(change.getName());
        identity.setPhone(change.getPhone());
        identity.setEmail(change.getEmail());
        identity.setStatus(targetStatus);
        identity.setEmployeeEnable(Boolean.FALSE.equals(change.getEnable()) ? 0 : 1);
        identity.setLeaveDate(change.getLeaveDate());
        identity.setOrgModifyTime(toLocalDateTime(change.getModifyTime()));
        identity.setSyncTime(LocalDateTime.now(ZoneOffset.UTC));
        if (existing == null) {
            identityMapper.insert(identity);
        } else {
            identityMapper.updateById(identity);
        }
        syncAccountToMpt(identity, previousStatus);
    }

    /**
     * 同步账号到 MPT（新员工开通、不可登录员工停用）；失败仅告警，不阻断同步
     */
    private void syncAccountToMpt(EiamIdentityPo identity, String previousStatus) {
        if (!provisionMpt) {
            return;
        }
        try {
            if (STATUS_ACTIVE.equals(identity.getStatus())) {
                boolean newlyActive = previousStatus == null || !STATUS_ACTIVE.equals(previousStatus);
                if (newlyActive) {
                    SysUser request = new SysUser();
                    request.setEmployeeId(identity.getEmployeeId());
                    request.setUserName(identity.getEmployeeCode());
                    request.setNickName(identity.getDisplayName());
                    request.setPhonenumber(identity.getPhone());
                    request.setEmail(identity.getEmail());
                    ApiResponse<SysUser> response = mptUserBindingClient.provision(request, SecurityConstants.INNER);
                    if (response == null || !"000000".equals(response.getCode())) {
                        String code = response == null ? "null" : response.getCode();
                        if (MPT_USER_NAME_CONFLICT.equals(code)) {
                            log.warn("MPT 工号冲突，需人工处理：employeeId={}, code={}", identity.getEmployeeId(), identity.getEmployeeCode());
                        } else {
                            log.warn("MPT 自动开通失败：employeeId={}, code={}", identity.getEmployeeId(), code);
                        }
                    }
                }
            } else if (previousStatus == null || STATUS_ACTIVE.equals(previousStatus)) {
                mptUserBindingClient.disableByEmployeeId(identity.getEmployeeId(), SecurityConstants.INNER);
            }
        } catch (Exception e) {
            log.warn("同步账号到 MPT 失败，将在下轮重试：employeeId={}", identity.getEmployeeId(), e);
        }
    }

    /**
     * 解析目标状态
     */
    String resolveStatus(EmployeeChangeExService change) {
        if (Boolean.FALSE.equals(change.getRowValid())) {
            return STATUS_DELETED;
        }
        if (Boolean.FALSE.equals(change.getEnable())) {
            return STATUS_DISABLED;
        }
        LocalDate leaveDate = change.getLeaveDate();
        if (leaveDate != null && !leaveDate.isAfter(LocalDate.now())) {
            return STATUS_LEFT;
        }
        return STATUS_ACTIVE;
    }

    private EiamSyncWatermarkPo loadWatermark() {
        return watermarkMapper.selectById(SOURCE_ORG);
    }

    /**
     * 保存水位（不存在则插入）
     */
    void saveWatermark(LocalDateTime watermark, String result, String message) {
        if (watermark == null) {
            return;
        }
        EiamSyncWatermarkPo po = EiamSyncWatermarkPo.builder()
                .source(SOURCE_ORG)
                .watermark(watermark)
                .lastSyncTime(LocalDateTime.now(ZoneOffset.UTC))
                .lastResult(result + ": " + message)
                .build();
        if (watermarkMapper.selectById(SOURCE_ORG) == null) {
            watermarkMapper.insert(po);
        } else {
            watermarkMapper.updateById(po);
        }
    }

    /**
     * 记录失败结果（不推进水位）
     */
    public void recordFailure(String message) {
        EiamSyncWatermarkPo existing = watermarkMapper.selectById(SOURCE_ORG);
        if (existing == null) {
            return;
        }
        existing.setLastResult("FAILED: " + message);
        existing.setLastSyncTime(LocalDateTime.now(ZoneOffset.UTC));
        watermarkMapper.updateById(existing);
    }

    private int effectivePageSize() {
        return pageSize <= 0 || pageSize > 500 ? 200 : pageSize;
    }

    private Long toEpochMilli(LocalDateTime value) {
        return value == null ? null : value.toInstant(ZoneOffset.UTC).toEpochMilli();
    }

    private LocalDateTime toLocalDateTime(Date date) {
        return date == null ? null : LocalDateTime.ofInstant(Instant.ofEpochMilli(date.getTime()), ZoneOffset.UTC);
    }
}
