package net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 同步水位（SEC-EIAM-DSN-CR-002）
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("eiam_sync_watermark")
public class EiamSyncWatermarkPo {

    /**
     * 来源
     */
    @TableId("source")
    private String source;

    /**
     * 已同步到的 ORG modify_time
     */
    private LocalDateTime watermark;

    /**
     * 最近成功同步时间
     */
    private LocalDateTime lastSyncTime;

    /**
     * 最近一次结果说明
     */
    private String lastResult;

}
