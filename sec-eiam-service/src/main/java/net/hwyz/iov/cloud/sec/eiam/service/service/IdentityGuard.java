package net.hwyz.iov.cloud.sec.eiam.service.service;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import net.hwyz.iov.cloud.framework.common.exception.ServiceException;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamIdentityMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamIdentityPo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDate;

/**
 * 身份目录登录校验（SEC-EIAM-DSN-CR-002 / US-028）
 * <p>
 * 员工必须在目录中处于 ACTIVE，且 ORG 侧启用、未到离职日期；未绑定账号的纯管理员（employeeId 为空）不在此校验范围。
 *
 * @author hwyz_leo
 */
@Service
public class IdentityGuard {

    /**
     * 目录状态：可登录
     */
    public static final String STATUS_ACTIVE = "ACTIVE";

    @Autowired
    private EiamIdentityMapper identityMapper;

    @Value("${eiam.identity.check-enabled:true}")
    private boolean checkEnabled;

    /**
     * 校验员工是否允许登录
     *
     * @param employeeId ORG 员工ID（为空表示纯管理员账号，跳过校验）
     */
    public void assertLoginAllowed(Long employeeId) {
        if (!checkEnabled || employeeId == null) {
            return;
        }
        EiamIdentityPo identity = findIdentity(employeeId);
        if (identity == null) {
            throw new ServiceException(EiamErrorCode.IDENTITY_NOT_FOUND.getMessage());
        }
        if (!STATUS_ACTIVE.equals(identity.getStatus())) {
            throw new ServiceException(EiamErrorCode.IDENTITY_NOT_ACTIVE.getMessage());
        }
        if (identity.getEmployeeEnable() == null || identity.getEmployeeEnable() != 1) {
            throw new ServiceException(EiamErrorCode.IDENTITY_NOT_ACTIVE.getMessage());
        }
        LocalDate leaveDate = identity.getLeaveDate();
        if (leaveDate != null && !leaveDate.isAfter(LocalDate.now())) {
            throw new ServiceException(EiamErrorCode.IDENTITY_NOT_ACTIVE.getMessage());
        }
    }

    /**
     * 查询目录中的员工身份
     *
     * @param employeeId ORG 员工ID
     * @return 身份记录（不存在返回 null）
     */
    public EiamIdentityPo findIdentity(Long employeeId) {
        return identityMapper.selectOne(Wrappers.<EiamIdentityPo>lambdaQuery()
                .eq(EiamIdentityPo::getSource, "ORG")
                .eq(EiamIdentityPo::getEmployeeId, employeeId)
                .last("limit 1"));
    }
}
