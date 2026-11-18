package net.hwyz.iov.cloud.sec.eiam.service.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * 身份目录列表项（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.7）
 * <p>
 * 不含任何密码哈希；仅暴露"是否已开通凭据/是否须改密/是否锁定"等派生状态。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdentityView {

    /**
     * ORG 员工ID
     */
    private Long employeeId;

    /**
     * 工号（EIAM 登录账号）
     */
    private String employeeCode;

    /**
     * 姓名
     */
    private String displayName;

    /**
     * 手机号
     */
    private String phone;

    /**
     * 目录状态：ACTIVE/DISABLED/LEFT/DELETED
     */
    private String status;

    /**
     * 离职日期
     */
    private LocalDate leaveDate;

    /**
     * 是否已开通 EIAM 凭据
     */
    private boolean credentialEnabled;

    /**
     * 是否必须修改密码
     */
    private boolean pwdResetRequired;

    /**
     * 是否处于锁定中
     */
    private boolean locked;

    /**
     * 最近一次改密/重置时间
     */
    private LocalDateTime lastChangeTime;
}
