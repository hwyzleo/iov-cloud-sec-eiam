-- SEC-EIAM-DSN-CR-002 §10.2：员工身份目录、同步水位与 OIDC 客户端
-- 身份目录数据来源于 EDD-ORG 员工主数据（增量同步 + 墓碑）；凭据仍由 EDD-MPT 持有。
CREATE TABLE IF NOT EXISTS `eiam_identity` (
    `uid`             BIGINT       NOT NULL AUTO_INCREMENT COMMENT '内部身份主键',
    `source`          VARCHAR(32)  NOT NULL DEFAULT 'ORG' COMMENT '来源：ORG',
    `employee_id`     BIGINT       NOT NULL COMMENT 'ORG 员工ID',
    `employee_code`   VARCHAR(50)  NOT NULL COMMENT '工号',
    `display_name`    VARCHAR(100) NOT NULL COMMENT '姓名',
    `phone`           VARCHAR(20)  DEFAULT NULL COMMENT '手机号',
    `email`           VARCHAR(100) DEFAULT NULL COMMENT '邮箱',
    `status`          VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE/DISABLED/LEFT/DELETED',
    `employee_enable` TINYINT      NOT NULL DEFAULT 1 COMMENT 'ORG 启用标记',
    `leave_date`      DATE         DEFAULT NULL COMMENT '离职日期',
    `org_modify_time` DATETIME(3)  NOT NULL COMMENT 'ORG 修改时间（水位）',
    `sync_time`       DATETIME(3)  NOT NULL COMMENT '最近一次同步时间',
    `create_time`     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `modify_time`     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '修改时间',
    PRIMARY KEY (`uid`),
    UNIQUE KEY `uk_source_employee` (`source`, `employee_id`),
    UNIQUE KEY `uk_source_code` (`source`, `employee_code`),
    KEY `idx_status` (`status`),
    KEY `idx_org_modify_time` (`org_modify_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='员工身份目录';

CREATE TABLE IF NOT EXISTS `eiam_sync_watermark` (
    `source`         VARCHAR(32)  NOT NULL COMMENT '来源',
    `watermark`      DATETIME(3)  NOT NULL COMMENT '已同步到的 ORG modify_time',
    `last_sync_time` DATETIME(3)  NOT NULL COMMENT '最近成功同步时间',
    `last_result`    VARCHAR(255) DEFAULT NULL COMMENT '最近一次结果说明',
    PRIMARY KEY (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='同步水位';

CREATE TABLE IF NOT EXISTS `eiam_oauth_client` (
    `client_id`     VARCHAR(64)  NOT NULL COMMENT '客户端ID（如 mpt）',
    `client_name`   VARCHAR(100) NOT NULL COMMENT '客户端名称',
    `redirect_uris` VARCHAR(500) NOT NULL COMMENT '回调地址白名单，逗号分隔（精确匹配）',
    `enabled`       TINYINT      NOT NULL DEFAULT 1 COMMENT '是否启用',
    `create_time`   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='OIDC 客户端';

-- 默认客户端：管理后台（回调地址按环境注入，此处仅占位，不做通配匹配）
INSERT INTO `eiam_oauth_client` (`client_id`, `client_name`, `redirect_uris`, `enabled`)
VALUES ('mpt', '管理后台', 'http://localhost/sso/callback', 1)
ON DUPLICATE KEY UPDATE `client_name` = VALUES(`client_name`);
