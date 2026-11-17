package net.hwyz.iov.cloud.sec.eiam.service.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.redis.service.RedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * OIDC 授权码存储（SEC-EIAM-DSN-CR-002 §10.4）
 * <p>
 * 授权码为短期一次性凭证，存 Redis（不落库）；取用即删，天然支持一次性消费。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class AuthorizationCodeStore {

    private static final String CODE_KEY_PREFIX = "eiam:oauth:code:";

    @Autowired
    private RedisService redisService;

    @Value("${eiam.oauth.code-ttl-seconds:60}")
    private long codeTtlSeconds;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 生成授权码
     *
     * @param clientId    客户端ID
     * @param employeeId  员工ID
     * @param redirectUri 回调地址
     * @return 授权码
     */
    public String issue(String clientId, Long employeeId, String redirectUri) {
        String code = UUID.randomUUID().toString().replace("-", "");
        AuthorizationCode payload = new AuthorizationCode(clientId, employeeId, redirectUri);
        try {
            redisService.setCacheObject(CODE_KEY_PREFIX + code, objectMapper.writeValueAsString(payload),
                    codeTtlSeconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new IllegalStateException("授权码生成失败", e);
        }
        return code;
    }

    /**
     * 消费授权码（一次性）
     *
     * @param code 授权码
     * @return 授权码内容；不存在或已过期返回 null
     */
    public AuthorizationCode consume(String code) {
        if (code == null || code.isBlank()) {
            return null;
        }
        String key = CODE_KEY_PREFIX + code;
        Object value = redisService.getCacheObject(key);
        if (value == null) {
            return null;
        }
        // 取用即删，保证一次性
        redisService.deleteObject(key);
        try {
            return objectMapper.readValue(String.valueOf(value), AuthorizationCode.class);
        } catch (Exception e) {
            log.warn("授权码解析失败：codeLength={}", code.length());
            return null;
        }
    }

    /**
     * 授权码内容
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthorizationCode {
        private String clientId;
        private Long employeeId;
        private String redirectUri;
    }
}
