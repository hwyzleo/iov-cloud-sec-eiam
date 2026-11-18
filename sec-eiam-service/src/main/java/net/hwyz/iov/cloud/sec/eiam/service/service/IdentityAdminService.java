package net.hwyz.iov.cloud.sec.eiam.service.service;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.mpt.api.constant.SecurityConstants;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import net.hwyz.iov.cloud.sec.eiam.service.client.MptUserBindingClient;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.exception.EiamBizException;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamIdentityMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamCredentialPo;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamIdentityPo;
import net.hwyz.iov.cloud.sec.eiam.service.vo.IdentityView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 身份目录管理（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.7）
 * <p>
 * 供管理后台「安全 → 身份目录」使用：目录分页、凭据重置、启用/停用（联动 MPT）、解锁。
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
public class IdentityAdminService {

    private static final String SOURCE_ORG = "ORG";

    private static final int MAX_PAGE_SIZE = 200;

    @Autowired
    private EiamIdentityMapper identityMapper;

    @Autowired
    private CredentialService credentialService;

    @Autowired
    private MptUserBindingClient mptUserBindingClient;

    /**
     * 目录分页查询
     *
     * @param key    关键词（工号/姓名/手机号，可空）
     * @param status 目录状态（可空）
     * @param page   页码（从 1 开始）
     * @param size   每页条数
     * @return 分页结果
     */
    public PageResult<IdentityView> list(String key, String status, int page, int size) {
        int pageNo = Math.max(page, 1);
        int pageSize = size <= 0 ? 10 : Math.min(size, MAX_PAGE_SIZE);
        LambdaQueryWrapper<EiamIdentityPo> query = Wrappers.<EiamIdentityPo>lambdaQuery()
                .eq(EiamIdentityPo::getSource, SOURCE_ORG)
                .eq(StrUtil.isNotBlank(status), EiamIdentityPo::getStatus, status)
                .and(StrUtil.isNotBlank(key), wrapper -> wrapper
                        .like(EiamIdentityPo::getEmployeeCode, key)
                        .or().like(EiamIdentityPo::getDisplayName, key)
                        .or().like(EiamIdentityPo::getPhone, key))
                .orderByDesc(EiamIdentityPo::getOrgModifyTime);
        Page<EiamIdentityPo> result = identityMapper.selectPage(new Page<>(pageNo, pageSize), query);
        List<EiamIdentityPo> records = result.getRecords();
        Map<Long, EiamCredentialPo> credentials = credentialService.findByUids(
                records.stream().map(EiamIdentityPo::getUid).collect(Collectors.toList()));
        List<IdentityView> items = records.stream()
                .map(identity -> toView(identity, credentials.get(identity.getUid())))
                .collect(Collectors.toList());
        return PageResult.<IdentityView>builder()
                .items(items)
                .total(result.getTotal())
                .page(pageNo)
                .size(pageSize)
                .build();
    }

    /**
     * 管理员重置密码
     *
     * @param employeeId ORG 员工ID
     * @return 一次性明文密码
     */
    public String resetPassword(Long employeeId) {
        EiamIdentityPo identity = requireIdentity(employeeId);
        return credentialService.resetPassword(identity.getUid());
    }

    /**
     * 启用：清凭据锁定 + 联动 MPT 启用账号
     *
     * @param employeeId ORG 员工ID
     * @return MPT 受影响账号数
     */
    public int enable(Long employeeId) {
        EiamIdentityPo identity = requireIdentity(employeeId);
        credentialService.unlock(identity.getUid());
        ApiResponse<Integer> response = mptUserBindingClient.enableByEmployeeId(employeeId, SecurityConstants.INNER);
        return requireMptOk(response, "启用");
    }

    /**
     * 停用：联动 MPT 停用账号（MPT 侧撤销在线会话）
     *
     * @param employeeId ORG 员工ID
     * @return MPT 受影响账号数
     */
    public int disable(Long employeeId) {
        requireIdentity(employeeId);
        ApiResponse<Integer> response = mptUserBindingClient.disableByEmployeeId(employeeId, SecurityConstants.INNER);
        return requireMptOk(response, "停用");
    }

    /**
     * 解锁：清空失败计数与锁定时间
     *
     * @param employeeId ORG 员工ID
     */
    public void unlock(Long employeeId) {
        EiamIdentityPo identity = requireIdentity(employeeId);
        credentialService.unlock(identity.getUid());
    }

    private EiamIdentityPo requireIdentity(Long employeeId) {
        if (employeeId == null) {
            throw new EiamBizException(EiamErrorCode.IDENTITY_NOT_FOUND);
        }
        EiamIdentityPo identity = identityMapper.selectOne(Wrappers.<EiamIdentityPo>lambdaQuery()
                .eq(EiamIdentityPo::getSource, SOURCE_ORG)
                .eq(EiamIdentityPo::getEmployeeId, employeeId)
                .last("limit 1"));
        if (identity == null) {
            throw new EiamBizException(EiamErrorCode.IDENTITY_NOT_FOUND);
        }
        return identity;
    }

    private IdentityView toView(EiamIdentityPo identity, EiamCredentialPo credential) {
        return IdentityView.builder()
                .employeeId(identity.getEmployeeId())
                .employeeCode(identity.getEmployeeCode())
                .displayName(identity.getDisplayName())
                .phone(identity.getPhone())
                .status(identity.getStatus())
                .leaveDate(identity.getLeaveDate())
                .credentialEnabled(credentialService.isEnabled(credential))
                .pwdResetRequired(credential != null && Integer.valueOf(1).equals(credential.getPwdResetRequired()))
                .locked(credentialService.isLocked(credential))
                .lastChangeTime(credential == null ? null : credential.getLastChangeTime())
                .build();
    }

    private int requireMptOk(ApiResponse<Integer> response, String action) {
        if (response == null || !"000000".equals(response.getCode())) {
            String message = response == null ? "MPT 无响应" : response.getMessage();
            log.warn("身份目录{}联动 MPT 失败：{}", action, message);
            throw new EiamBizException(EiamErrorCode.MPT_USER_BINDING_MISSING, "MPT 账号" + action + "失败：" + message);
        }
        return response.getData() == null ? 0 : response.getData();
    }
}
