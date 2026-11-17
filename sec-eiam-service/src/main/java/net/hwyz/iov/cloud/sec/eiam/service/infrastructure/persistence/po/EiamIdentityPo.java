package net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * 员工身份目录（SEC-EIAM-DSN-CR-002）
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("eiam_identity")
public class EiamIdentityPo {

    /**
     * 内部身份主键
     */
    @TableId(value = "uid", type = IdType.AUTO)
    private Long uid;

    /**
     * 来源（ORG）
     */
    private String source;

    /**
     * ORG 员工ID
     */
    private Long employeeId;

    /**
     * 工号
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
     * 邮箱
     */
    private String email;

    /**
     * 状态：ACTIVE/DISABLED/LEFT/DELETED
     */
    private String status;

    /**
     * ORG 启用标记
     */
    private Integer employeeEnable;

    /**
     * 离职日期
     */
    private LocalDate leaveDate;

    /**
     * ORG 修改时间（水位）
     */
    private LocalDateTime orgModifyTime;

    /**
     * 最近一次同步时间
     */
    private LocalDateTime syncTime;

}
