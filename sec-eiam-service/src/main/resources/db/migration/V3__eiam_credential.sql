-- SEC-EIAM-DSN-CR-002 原地修订（第二次）§13.2：EIAM 自持员工登录凭据
-- 凭据属主归 EIAM：MPT 仅保留本地账密登录的 sys_user.password（两个密码互不同步，本期接受）。
-- uid 与 eiam_identity.uid 为逻辑关联，不建 DB 外键（身份同步与凭据生命周期互不阻塞）。
CREATE TABLE IF NOT EXISTS `eiam_credential` (
    `uid`                BIGINT       NOT NULL COMMENT '身份主键（逻辑关联 eiam_identity.uid）',
    `password_hash`      VARCHAR(100) DEFAULT NULL COMMENT 'BCrypt 密码哈希',
    `pwd_reset_required` TINYINT      NOT NULL DEFAULT 0 COMMENT '是否必须修改密码：0否 1是',
    `failed_count`       INT          NOT NULL DEFAULT 0 COMMENT '连续密码错误次数',
    `locked_until`       DATETIME(3)  DEFAULT NULL COMMENT '锁定截止时间',
    `last_change_time`   DATETIME(3)  DEFAULT NULL COMMENT '最近一次改密/重置时间',
    `create_time`        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间（首次惰性迁移时间）',
    `modify_time`        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '修改时间',
    PRIMARY KEY (`uid`),
    KEY `idx_locked_until` (`locked_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='EIAM 员工登录凭据';
