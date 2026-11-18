package net.hwyz.iov.cloud.sec.eiam.service.service;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.mpt.api.constant.SecurityConstants;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.exception.ServiceException;
import net.hwyz.iov.cloud.framework.web.constant.MptConstants;
import net.hwyz.iov.cloud.sec.eiam.service.client.MptUserBindingClient;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.exception.EiamBizException;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamIdentityMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamIdentityPo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * EIAM 单点登录凭据认证（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.5）
 * <p>
 * 与 MPT 本地账密登录（`/login` → {@link SysLoginService}）并行且互不影响：
 * 本服务只校验 EIAM 自有凭据，成功后按 `employeeId` 经 MPT 内部契约装配账号与权限。
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
public class EiamSsoLoginService {

    /**
     * 目录来源
     */
    private static final String SOURCE_ORG = "ORG";

    /**
     * MPT 内部契约错误码
     */
    private static final String MPT_BINDING_MISSING = "100101";
    private static final String MPT_USER_DISABLED = "100103";

    @Autowired
    private EiamIdentityMapper identityMapper;

    @Autowired
    private CredentialService credentialService;

    @Autowired
    private IdentityGuard identityGuard;

    @Autowired
    private MptUserBindingClient mptUserBindingClient;

    @Autowired
    private SysRecordLogService recordLogService;

    /**
     * EIAM 登录页认证：EIAM 凭据校验 → 目录校验 → MPT 装配账号与权限
     *
     * @param username 工号（eiam_identity.employee_code）
     * @param password 明文密码
     * @return 登录用户（含 employeeId、权限）
     */
    public LoginUser authenticate(String username, String password) {
        if (StrUtil.hasBlank(username, password)) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT, "工号/密码必须填写");
        }
        try {
            EiamIdentityPo identity = requireIdentityByCode(username);
            identityGuard.assertLoginAllowed(identity.getEmployeeId());
            credentialService.verify(identity, password);
            LoginUser loginUser = loadLoginUser(identity.getEmployeeId());
            recordLogService.recordLogininfor(username, MptConstants.LOGIN_SUCCESS, "EIAM 凭据登录成功");
            return loginUser;
        } catch (RuntimeException e) {
            recordLogService.recordLogininfor(username, MptConstants.LOGIN_FAIL, failureMessage(e));
            throw e;
        }
    }

    /**
     * 强制改密后的自动登录：校验旧密码 → 更新为新密码 → 装配账号与权限
     *
     * @param username    工号
     * @param oldPassword 旧密码
     * @param newPassword 新密码
     * @return 登录用户
     */
    public LoginUser changePasswordAndLoad(String username, String oldPassword, String newPassword) {
        if (StrUtil.hasBlank(username, oldPassword, newPassword)) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT, "工号/旧密码/新密码必须填写");
        }
        EiamIdentityPo identity = requireIdentityByCode(username);
        identityGuard.assertLoginAllowed(identity.getEmployeeId());
        credentialService.changePassword(identity.getUid(), oldPassword, newPassword);
        recordLogService.recordLogininfor(username, MptConstants.LOGIN_SUCCESS, "EIAM 凭据改密成功");
        return loadLoginUser(identity.getEmployeeId());
    }

    /**
     * 按工号定位目录身份（source=ORG）
     */
    public EiamIdentityPo requireIdentityByCode(String employeeCode) {
        EiamIdentityPo identity = identityMapper.selectOne(Wrappers.<EiamIdentityPo>lambdaQuery()
                .eq(EiamIdentityPo::getSource, SOURCE_ORG)
                .eq(EiamIdentityPo::getEmployeeCode, employeeCode)
                .last("limit 1"));
        if (identity == null) {
            throw new EiamBizException(EiamErrorCode.IDENTITY_NOT_FOUND);
        }
        return identity;
    }

    /**
     * 按员工ID加载 MPT 登录用户（账号 + 角色 + 权限）
     *
     * @param employeeId ORG 员工ID
     * @return 登录用户
     */
    public LoginUser loadLoginUser(Long employeeId) {
        ApiResponse<LoginUser> response = mptUserBindingClient.getUserByEmployeeId(employeeId, SecurityConstants.INNER);
        if (response == null) {
            throw new EiamBizException(EiamErrorCode.MPT_USER_BINDING_MISSING);
        }
        if (!"000000".equals(response.getCode())) {
            if (MPT_BINDING_MISSING.equals(response.getCode())) {
                throw new EiamBizException(EiamErrorCode.MPT_USER_BINDING_MISSING);
            }
            if (MPT_USER_DISABLED.equals(response.getCode())) {
                throw new EiamBizException(EiamErrorCode.IDENTITY_NOT_ACTIVE);
            }
            throw new ServiceException(response.getMessage());
        }
        LoginUser loginUser = response.getData();
        if (loginUser == null) {
            throw new EiamBizException(EiamErrorCode.MPT_USER_BINDING_MISSING);
        }
        // 会话携带员工标识，供下游服务定位员工主数据
        loginUser.setEmployeeId(employeeId);
        return loginUser;
    }

    private String failureMessage(RuntimeException e) {
        if (e instanceof EiamBizException bizException) {
            return bizException.getMessage();
        }
        return e.getMessage() == null ? "登录失败" : e.getMessage();
    }
}
