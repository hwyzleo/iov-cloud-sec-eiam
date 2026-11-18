package net.hwyz.iov.cloud.sec.eiam.service.service;

import cn.hutool.core.util.RandomUtil;
import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.mpt.api.RemoteUserService;
import net.hwyz.iov.cloud.edd.mpt.api.domain.SysUser;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.constant.MptUserConstants;
import net.hwyz.iov.cloud.framework.common.constant.SecurityConstants;
import net.hwyz.iov.cloud.framework.common.exception.ServiceException;
import net.hwyz.iov.cloud.framework.security.util.SecurityUtils;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.exception.EiamBizException;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamCredentialMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamCredentialPo;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamIdentityPo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * EIAM 员工登录凭据服务（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.3 / §13.4）
 * <p>
 * 凭据属主归 EIAM：本地 BCrypt 校验、失败锁定、惰性迁移（首次登录用 MPT 密码校验一次并落库哈希）、
 * 管理员重置与自助改密。EIAM 登录页不再直接使用 MPT 校验密码。
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
public class CredentialService {

    /**
     * 随机密码字符集：去除易混淆字符（0/O/1/l/I）
     */
    private static final String PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";

    /**
     * 重置密码长度下限 / 上限
     */
    private static final int RESET_LENGTH_MIN = 12;
    private static final int RESET_LENGTH_MAX = 16;

    @Autowired
    private EiamCredentialMapper credentialMapper;

    @Autowired
    private RemoteUserService remoteUserService;

    @Value("${eiam.credential.max-failed:5}")
    private int maxFailed;

    @Value("${eiam.credential.lock-minutes:15}")
    private long lockMinutes;

    @Value("${eiam.credential.reset-password-length:14}")
    private int resetPasswordLength;

    @Value("${eiam.credential.lazy-migration-enabled:true}")
    private boolean lazyMigrationEnabled;

    /**
     * 查询凭据
     *
     * @param uid 身份主键
     * @return 凭据（不存在返回 null）
     */
    public EiamCredentialPo findByUid(Long uid) {
        if (uid == null) {
            return null;
        }
        return credentialMapper.selectById(uid);
    }

    /**
     * 批量查询凭据（目录列表展示，避免 N+1）
     *
     * @param uids 身份主键集合
     * @return uid → 凭据
     */
    public Map<Long, EiamCredentialPo> findByUids(Collection<Long> uids) {
        if (uids == null || uids.isEmpty()) {
            return Collections.emptyMap();
        }
        List<EiamCredentialPo> list = credentialMapper.selectList(Wrappers.<EiamCredentialPo>query()
                .in("uid", uids));
        Map<Long, EiamCredentialPo> map = new HashMap<>(list.size());
        for (EiamCredentialPo credential : list) {
            map.put(credential.getUid(), credential);
        }
        return map;
    }

    /**
     * 校验 EIAM 登录凭据（含惰性迁移）
     * <p>
     * 通过返回凭据记录；任一环节失败抛出带错误码的业务异常：
     * 401008 凭据不存在、401009 密码错误、401010 账号锁定、401011 必须修改密码。
     *
     * @param identity    目录身份
     * @param rawPassword 明文密码
     * @return 凭据记录（已通过校验）
     */
    public EiamCredentialPo verify(EiamIdentityPo identity, String rawPassword) {
        if (identity == null || identity.getUid() == null) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_NOT_FOUND);
        }
        if (StrUtil.isBlank(rawPassword)) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT);
        }
        EiamCredentialPo credential = findByUid(identity.getUid());
        if (credential == null) {
            credential = migrate(identity, rawPassword);
        } else {
            assertNotLocked(credential);
            if (!matches(credential, rawPassword)) {
                onPasswordFailure(credential);
                // onPasswordFailure 必定抛出异常，此处仅为编译可达性
                throw new EiamBizException(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT);
            }
            onSuccess(credential);
        }
        if (Integer.valueOf(1).equals(credential.getPwdResetRequired())) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_PWD_RESET_REQUIRED);
        }
        return credential;
    }

    /**
     * 惰性迁移：无凭据记录时用 MPT 密码校验一次，成功后把 MPT 的 BCrypt 哈希写入 eiam_credential。
     * <p>
     * 仅在一次登录中尝试；MPT 密码一旦落库，EIAM 即为凭据属主，MPT 改密不再影响 EIAM。
     *
     * @param identity    目录身份
     * @param rawPassword 明文密码
     * @return 新建的凭据记录
     */
    private EiamCredentialPo migrate(EiamIdentityPo identity, String rawPassword) {
        if (!lazyMigrationEnabled) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_NOT_FOUND);
        }
        if (StrUtil.isBlank(identity.getEmployeeCode())) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_NOT_FOUND);
        }
        ApiResponse<LoginUser> response = remoteUserService.getUserInfo(identity.getEmployeeCode(), SecurityConstants.INNER);
        if (response == null || !"000000".equals(response.getCode()) || response.getData() == null) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_NOT_FOUND);
        }
        SysUser sysUser = response.getData().getSysUser();
        if (sysUser == null || StrUtil.isBlank(sysUser.getPassword())) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_NOT_FOUND);
        }
        if (!Objects.equals(sysUser.getEmployeeId(), identity.getEmployeeId())) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_NOT_FOUND);
        }
        if (!SecurityUtils.matchesPassword(rawPassword, sysUser.getPassword())) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT);
        }
        EiamCredentialPo credential = EiamCredentialPo.builder()
                .uid(identity.getUid())
                .passwordHash(sysUser.getPassword())
                .pwdResetRequired(Integer.valueOf(1).equals(sysUser.getPwdResetRequired()) ? 1 : 0)
                .failedCount(0)
                .lastChangeTime(LocalDateTime.now())
                .build();
        credentialMapper.insert(credential);
        log.info("EIAM 凭据惰性迁移完成：uid={}, employeeId={}", identity.getUid(), identity.getEmployeeId());
        return credential;
    }

    /**
     * 管理员重置密码：随机 12~16 位、BCrypt 落库、标记必须改密、清锁定与失败计数
     *
     * @param uid 身份主键
     * @return 一次性明文密码（仅本次调用返回）
     */
    public String resetPassword(Long uid) {
        if (uid == null) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_NOT_FOUND);
        }
        String plainPassword = RandomUtil.randomString(PASSWORD_CHARS, effectiveResetLength());
        String passwordHash = SecurityUtils.encryptPassword(plainPassword);
        LocalDateTime now = LocalDateTime.now();
        EiamCredentialPo credential = findByUid(uid);
        if (credential == null) {
            credentialMapper.insert(EiamCredentialPo.builder()
                    .uid(uid)
                    .passwordHash(passwordHash)
                    .pwdResetRequired(1)
                    .failedCount(0)
                    .lastChangeTime(now)
                    .build());
        } else {
            credentialMapper.update(null, Wrappers.<EiamCredentialPo>update()
                    .eq("uid", uid)
                    .set("password_hash", passwordHash)
                    .set("pwd_reset_required", 1)
                    .set("failed_count", 0)
                    .set("locked_until", null)
                    .set("last_change_time", now));
        }
        log.info("EIAM 凭据已重置：uid={}（一次性明文仅返回给管理员）", uid);
        return plainPassword;
    }

    /**
     * 自助修改密码：校验旧密码后更新哈希，清除必须改密标记与锁定
     *
     * @param uid         身份主键
     * @param oldPassword 旧密码
     * @param newPassword 新密码
     */
    public void changePassword(Long uid, String oldPassword, String newPassword) {
        EiamCredentialPo credential = findByUid(uid);
        if (credential == null) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_NOT_FOUND);
        }
        assertNotLocked(credential);
        if (!matches(credential, oldPassword)) {
            onPasswordFailure(credential);
        }
        if (StrUtil.isBlank(newPassword)
                || newPassword.length() < MptUserConstants.PASSWORD_MIN_LENGTH
                || newPassword.length() > MptUserConstants.PASSWORD_MAX_LENGTH) {
            throw new ServiceException(String.format("新密码长度必须在%d到%d个字符之间",
                    MptUserConstants.PASSWORD_MIN_LENGTH, MptUserConstants.PASSWORD_MAX_LENGTH));
        }
        if (newPassword.equals(oldPassword)) {
            throw new ServiceException("新密码不能与旧密码相同");
        }
        credentialMapper.update(null, Wrappers.<EiamCredentialPo>update()
                .eq("uid", uid)
                .set("password_hash", SecurityUtils.encryptPassword(newPassword))
                .set("pwd_reset_required", 0)
                .set("failed_count", 0)
                .set("locked_until", null)
                .set("last_change_time", LocalDateTime.now()));
        log.info("EIAM 凭据已修改：uid={}", uid);
    }

    /**
     * 解锁：清空失败计数与锁定时间
     *
     * @param uid 身份主键
     */
    public void unlock(Long uid) {
        if (uid == null) {
            return;
        }
        credentialMapper.update(null, Wrappers.<EiamCredentialPo>update()
                .eq("uid", uid)
                .set("failed_count", 0)
                .set("locked_until", null));
    }

    /**
     * 校验密码是否匹配（BCrypt）
     *
     * @param credential  凭据
     * @param rawPassword 明文密码
     * @return 是否匹配
     */
    public boolean matches(EiamCredentialPo credential, String rawPassword) {
        if (credential == null || StrUtil.isBlank(credential.getPasswordHash()) || StrUtil.isBlank(rawPassword)) {
            return false;
        }
        try {
            return SecurityUtils.matchesPassword(rawPassword, credential.getPasswordHash());
        } catch (IllegalArgumentException e) {
            // 哈希格式非法（历史脏数据）：按密码错误处理，不泄露内部细节
            log.warn("EIAM 凭据哈希格式非法：uid={}", credential.getUid());
            return false;
        }
    }

    /**
     * 是否已开通凭据
     *
     * @param credential 凭据（可为 null）
     * @return 是否已开通
     */
    public boolean isEnabled(EiamCredentialPo credential) {
        return credential != null && StrUtil.isNotBlank(credential.getPasswordHash());
    }

    /**
     * 是否处于锁定中
     *
     * @param credential 凭据（可为 null）
     * @return 是否锁定
     */
    public boolean isLocked(EiamCredentialPo credential) {
        return credential != null && credential.getLockedUntil() != null
                && credential.getLockedUntil().isAfter(LocalDateTime.now());
    }

    /**
     * 锁定校验：锁定中直接拒绝（不校验密码）
     */
    private void assertNotLocked(EiamCredentialPo credential) {
        if (isLocked(credential)) {
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_ACCOUNT_LOCKED);
        }
        if (credential.getLockedUntil() != null) {
            // 锁定已过期：清除锁定与计数，允许重新校验
            unlock(credential.getUid());
            credential.setLockedUntil(null);
            credential.setFailedCount(0);
        }
    }

    /**
     * 密码错误：累加失败次数，达到阈值时锁定并返回锁定错误
     */
    private void onPasswordFailure(EiamCredentialPo credential) {
        int failed = (credential.getFailedCount() == null ? 0 : credential.getFailedCount()) + 1;
        if (failed >= effectiveMaxFailed()) {
            credentialMapper.update(null, Wrappers.<EiamCredentialPo>update()
                    .eq("uid", credential.getUid())
                    .set("failed_count", failed)
                    .set("locked_until", LocalDateTime.now().plusMinutes(lockMinutes)));
            log.warn("EIAM 凭据连续错误达到阈值已锁定：uid={}, failed={}, lockMinutes={}",
                    credential.getUid(), failed, lockMinutes);
            throw new EiamBizException(EiamErrorCode.CREDENTIAL_ACCOUNT_LOCKED,
                    String.format("密码连续错误%d次，账号已锁定%d分钟", maxFailed, lockMinutes));
        }
        credentialMapper.update(null, Wrappers.<EiamCredentialPo>update()
                .eq("uid", credential.getUid())
                .set("failed_count", failed));
        throw new EiamBizException(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT);
    }

    /**
     * 校验成功：清零失败计数与锁定（仅在存在脏值时更新）
     */
    private void onSuccess(EiamCredentialPo credential) {
        int failed = credential.getFailedCount() == null ? 0 : credential.getFailedCount();
        if (failed > 0 || credential.getLockedUntil() != null) {
            unlock(credential.getUid());
        }
        credential.setFailedCount(0);
        credential.setLockedUntil(null);
    }

    private int effectiveMaxFailed() {
        return maxFailed > 0 ? maxFailed : 5;
    }

    private int effectiveResetLength() {
        if (resetPasswordLength < RESET_LENGTH_MIN || resetPasswordLength > RESET_LENGTH_MAX) {
            return 14;
        }
        return resetPasswordLength;
    }
}
