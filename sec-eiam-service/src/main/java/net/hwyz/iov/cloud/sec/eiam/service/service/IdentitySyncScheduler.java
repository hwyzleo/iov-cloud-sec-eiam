package net.hwyz.iov.cloud.sec.eiam.service.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 员工身份目录同步调度（SEC-EIAM-DSN-CR-002 / US-026）
 * <p>
 * 失败时保留水位与目录数据，仅记录失败结果并等待下一轮（退避由间隔体现），不推进水位。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class IdentitySyncScheduler {

    @Autowired
    private IdentitySyncService identitySyncService;

    /**
     * 定时增量同步
     */
    @Scheduled(fixedDelayString = "${eiam.sync.interval-ms:300000}", initialDelayString = "${eiam.sync.initial-delay-ms:30000}")
    public void sync() {
        try {
            int changes = identitySyncService.syncOnce();
            if (changes > 0) {
                log.info("员工目录同步完成：本次处理 {} 条变更", changes);
            }
        } catch (Exception e) {
            log.error("员工目录同步失败，保留原水位等待重试", e);
            identitySyncService.recordFailure(e.getMessage());
        }
    }
}
