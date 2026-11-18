package net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * EIAM 员工登录凭据（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.2）
 * <p>
 * `uid` 逻辑关联 {@link EiamIdentityPo#getUid()}，不建 DB 外键；身份同步任务不触碰该表。
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("eiam_credential")
public class EiamCredentialPo {

    /**
     * 身份主键（eiam_identity.uid）
     */
    @TableId(value = "uid", type = IdType.INPUT)
    private Long uid;

    /**
     * BCrypt 密码哈希
     */
    private String passwordHash;

    /**
     * 是否必须修改密码：0否 1是
     */
    private Integer pwdResetRequired;

    /**
     * 连续密码错误次数
     */
    private Integer failedCount;

    /**
     * 锁定截止时间
     */
    private LocalDateTime lockedUntil;

    /**
     * 最近一次改密/重置时间
     */
    private LocalDateTime lastChangeTime;

    /**
     * 创建时间
     */
    private LocalDateTime createTime;

    /**
     * 修改时间
     */
    private LocalDateTime modifyTime;
}
