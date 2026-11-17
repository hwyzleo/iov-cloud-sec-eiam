package net.hwyz.iov.cloud.sec.eiam.service.oauth;

import net.hwyz.iov.cloud.framework.redis.service.RedisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * SEC-EIAM-DSN-CR-002 / US-027：授权码一次性消费测试。
 *
 * @author hwyz_leo
 * @since 2026-11-17
 */
class AuthorizationCodeStoreTest {

    private RedisService redisService;
    private AuthorizationCodeStore codeStore;
    private final Map<String, Object> store = new HashMap<>();

    @BeforeEach
    void setUp() {
        store.clear();
        redisService = mock(RedisService.class);
        org.mockito.Mockito.doAnswer(inv -> {
            store.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(redisService).setCacheObject(anyString(), any(), anyLong(), any());
        when(redisService.getCacheObject(anyString())).thenAnswer(inv -> store.get(inv.getArgument(0)));
        when(redisService.deleteObject(anyString())).thenAnswer(inv -> store.remove(inv.getArgument(0)) != null);
        codeStore = new AuthorizationCodeStore();
        ReflectionTestUtils.setField(codeStore, "redisService", redisService);
        ReflectionTestUtils.setField(codeStore, "codeTtlSeconds", 60L);
    }

    @Test
    @DisplayName("授权码签发后可消费一次，内容与签发参数一致")
    void issueThenConsumeOnce() {
        String code = codeStore.issue("mpt", 1001L, "https://admin.example.com/sso/callback");
        assertNotNull(code);

        AuthorizationCodeStore.AuthorizationCode payload = codeStore.consume(code);
        assertNotNull(payload);
        assertEquals("mpt", payload.getClientId());
        assertEquals(1001L, payload.getEmployeeId());
        assertEquals("https://admin.example.com/sso/callback", payload.getRedirectUri());

        // 一次性：第二次消费返回 null
        assertNull(codeStore.consume(code));
        verify(redisService, org.mockito.Mockito.times(1)).deleteObject(eq("eiam:oauth:code:" + code));
    }

    @Test
    @DisplayName("不存在的授权码返回 null")
    void consumeUnknownCode() {
        assertNull(codeStore.consume("not-exist"));
        assertNull(codeStore.consume(null));
        assertNull(codeStore.consume(" "));
    }
}
