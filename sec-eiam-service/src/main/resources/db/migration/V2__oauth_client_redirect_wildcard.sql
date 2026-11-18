-- SEC-EIAM-DSN-CR-002 §12.3：默认回调占位无法匹配实际后台域名，改为通配占位以支持多环境。
-- 仅当仍为初始占位值时替换，避免覆盖已按环境配置的地址。
-- 生产建议：将 redirect_uris 收敛为管理后台精确地址（见 CR 说明）。
UPDATE `eiam_oauth_client`
SET `redirect_uris` = 'http://*/sso/callback,https://*/sso/callback'
WHERE `client_id` = 'mpt'
  AND `redirect_uris` = 'http://localhost/sso/callback';
