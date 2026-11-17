package net.hwyz.iov.cloud.sec.eiam.service;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import net.hwyz.iov.cloud.edd.mpt.api.RemoteLogService;
import net.hwyz.iov.cloud.edd.mpt.api.RemoteUserService;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.constant.SecurityConstants;
import net.hwyz.iov.cloud.framework.redis.service.RedisService;
import net.hwyz.iov.cloud.framework.security.service.TokenService;
import net.hwyz.iov.cloud.framework.security.util.SecurityUtils;
import net.hwyz.iov.cloud.framework.web.autoconfigure.IovJacksonAutoConfiguration;
import net.hwyz.iov.cloud.sec.eiam.service.config.EiamJacksonConfig;
import net.hwyz.iov.cloud.sec.eiam.service.controller.TokenController;
import net.hwyz.iov.cloud.sec.eiam.service.form.LoginBody;
import net.hwyz.iov.cloud.sec.eiam.service.form.RegisterBody;
import net.hwyz.iov.cloud.sec.eiam.service.service.SysLoginService;
import net.hwyz.iov.cloud.sec.eiam.service.service.SysPasswordService;
import net.hwyz.iov.cloud.sec.eiam.service.service.SysRecordLogService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.FeignAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;

import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * MPT 响应解码与登录链路集成测试（SEC-EIAM-DSN-CR-001，TC-001-06 / TC-001-07 / TC-001-08）。
 * <p>
 * 使用真实 Spring 装配的生产 {@code ObjectMapper}（Boot Jackson 自动配置 + framework
 * {@code IovJacksonAutoConfiguration} + EIAM {@link EiamJacksonConfig}）、真实
 * {@link RemoteUserService} Feign 代理（Spring Cloud OpenFeign 装配，含生产
 * {@code SpringDecoder}/{@code SpringEncoder}）访问本地 HTTP stub，并驱动真实
 * {@link SysLoginService}：Redis 密码重试存储、登录日志与 token 签发按 CR 允许被隔离，
 * 响应解码与登录编排必须走真实实现。
 *
 * @author hwyz_leo
 * @since 2026-11-16
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = MptLoginDecodeIntegrationTest.TestApplication.class)
class MptLoginDecodeIntegrationTest {

    static {
        // 宿主代理配置在类加载时清空，避免干扰本机回环 HTTP 断言（仅测试传输层）
        System.setProperty("http.proxyHost", "");
        System.setProperty("http.proxyPort", "");
    }

    private static final Instant SAMPLE = Instant.parse("2024-11-29T10:22:30Z");
    private static final String PASSWORD_HASH = SecurityUtils.encryptPassword("admin123");
    private static final String ISO_JSON = "\"2024-11-29T10:22:30.000Z\"";
    private static final String ISO_OFFSET_JSON = "\"2024-11-29T18:22:30+08:00\"";
    private static final String LEGACY_JSON = "\"2024-11-29 18:22:30\"";

    private static final AtomicReference<String> USER_INFO_BODY = new AtomicReference<>();
    private static final List<String> RECORD_LOGIN_BODIES = new CopyOnWriteArrayList<>();
    private static final List<String> REGISTERED_BODIES = new CopyOnWriteArrayList<>();

    private static HttpServer server;
    private static ExecutorService executor;
    private static int port;

    static {
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
            server.createContext("/user/info/", exchange -> respond(exchange, USER_INFO_BODY.get()));
            server.createContext("/user/recordlogin",
                    exchange -> respond(exchange, capture(exchange, RECORD_LOGIN_BODIES)));
            server.createContext("/user/register",
                    exchange -> respond(exchange, capture(exchange, REGISTERED_BODIES)));
            executor = Executors.newCachedThreadPool();
            server.setExecutor(executor);
            server.start();
            port = server.getAddress().getPort();
        } catch (IOException e) {
            throw new IllegalStateException("启动本地 MPT stub 失败", e);
        }
    }

    @DynamicPropertySource
    static void mptStubUrl(DynamicPropertyRegistry registry) {
        registry.add("spring.cloud.openfeign.client.config.remoteUserService.url",
                () -> "http://127.0.0.1:" + port);
        registry.add("iov.web.jackson.date-format", () -> "iso");
        registry.add("iov.web.jackson.zone-id", () -> "Asia/Shanghai");
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    @BeforeEach
    void resetStub() {
        Mockito.clearInvocations(redisService);
        USER_INFO_BODY.set(loginUserJson(ISO_JSON, ISO_JSON));
        RECORD_LOGIN_BODIES.clear();
        REGISTERED_BODIES.clear();
    }

    @Autowired
    private RemoteUserService remoteUserService;

    @Autowired
    private SysLoginService sysLoginService;

    @Autowired
    private RedisService redisService;

    // ---------- TC-001-06：真实 Feign 解码三种已批准输入 ----------

    @Test
    void feign解码_ISO带Z_嵌套Date瞬时正确()  {
        USER_INFO_BODY.set(loginUserJson(ISO_JSON, ISO_JSON));

        ApiResponse<LoginUser> response = remoteUserService.getUserInfo("admin", SecurityConstants.INNER);

        assertDecoded(response, SAMPLE);
    }

    @Test
    void feign解码_ISO带offset_嵌套Date瞬时正确()  {
        USER_INFO_BODY.set(loginUserJson(ISO_OFFSET_JSON, ISO_OFFSET_JSON));

        ApiResponse<LoginUser> response = remoteUserService.getUserInfo("admin", SecurityConstants.INNER);

        assertDecoded(response, SAMPLE);
    }

    @Test
    void feign解码_legacy墙上时间按配置时区_嵌套Date瞬时正确()  {
        USER_INFO_BODY.set(loginUserJson(LEGACY_JSON, LEGACY_JSON));

        ApiResponse<LoginUser> response = remoteUserService.getUserInfo("admin", SecurityConstants.INNER);

        assertDecoded(response, SAMPLE);
    }

    @Test
    void feign解码_epoch毫秒_嵌套Date瞬时正确()  {
        USER_INFO_BODY.set(loginUserJson(String.valueOf(SAMPLE.toEpochMilli()),
                String.valueOf(SAMPLE.toEpochMilli())));

        ApiResponse<LoginUser> response = remoteUserService.getUserInfo("admin", SecurityConstants.INNER);

        assertDecoded(response, SAMPLE);
    }

    private static void assertDecoded(ApiResponse<LoginUser> response, Instant expected) {
        assertThat(response).isNotNull();
        assertThat(response.getCode()).isEqualTo("000000");
        LoginUser loginUser = response.getData();
        assertThat(loginUser).isNotNull();
        assertThat(loginUser.getSysUser()).isNotNull();
        assertThat(loginUser.getSysUser().getUserName()).isEqualTo("admin");
        assertThat(loginUser.getSysUser().getCreateTime()).isEqualTo(Date.from(expected));
        assertThat(loginUser.getSysUser().getUpdateTime()).isEqualTo(Date.from(expected));
    }

    // ---------- TC-001-07：真实 SysLoginService 编排 ----------

    @Test
    void login_解码成功后执行密码校验并返回完整LoginUser()  {
        USER_INFO_BODY.set(loginUserJson(ISO_JSON, ISO_JSON));

        LoginUser loginUser = sysLoginService.login("admin", "admin123");

        assertThat(loginUser).isNotNull();
        assertThat(loginUser.getSysUser().getUserId()).isEqualTo(1L);
        assertThat(loginUser.getSysUser().getUserName()).isEqualTo("admin");
        assertThat(loginUser.getSysUser().getCreateTime()).isEqualTo(Date.from(SAMPLE));
        // 密码校验真实执行（命中重试缓存清除路径）
        Mockito.verify(redisService).hasKey(Mockito.anyString());
    }

    @Test
    void login_非法Date_解码失败阻断登录且不伪造用户()  {
        USER_INFO_BODY.set(loginUserJson("\"not-a-date\"", ISO_JSON));

        Throwable thrown = catchThrowable(() -> sysLoginService.login("admin", "admin123"));
        assertThat(thrown).isNotNull();
        // 解耦外层包装：Feign/Spring 可能包装为 DecodeException / RestClientException
        assertThat(messageChain(thrown))
                .anyMatch(message -> message.contains("Date 仅支持带 offset 的 ISO-8601 字符串"))
                .anyMatch(message -> message.contains("not-a-date"));
        // 解码失败发生在凭证校验之前：未进入密码校验，也未回写登录信息
        Mockito.verify(redisService, Mockito.never()).hasKey(Mockito.anyString());
        assertThat(RECORD_LOGIN_BODIES).isEmpty();
    }

    // ---------- TC-001-08：MPT 请求契约与 EIAM 响应结构 ----------

    @Test
    void recordUserLogin请求_loginDate遵循frameworkISO写契约()  {
        USER_INFO_BODY.set(loginUserJson(ISO_JSON, ISO_JSON));

        sysLoginService.login("admin", "admin123");

        assertThat(RECORD_LOGIN_BODIES).hasSize(1);
        String body = RECORD_LOGIN_BODIES.get(0);
        assertThat(body).contains("\"userId\":1");
        String loginDate = extractText(body, "loginDate");
        assertThat(loginDate).matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z");
        Instant loginInstant = Instant.parse(loginDate);
        assertThat(Duration.between(loginInstant, Instant.now()).abs()).isLessThan(Duration.ofMinutes(5));
    }

    @Test
    void 响应结构_login仅含token字段_其余接口数据结构不变()  {
        USER_INFO_BODY.set(loginUserJson(ISO_JSON, ISO_JSON));

        TokenService tokenService = Mockito.mock(TokenService.class);
        Mockito.when(tokenService.createToken(Mockito.any(LoginUser.class)))
                .thenReturn(Map.of("access_token", "test-token", "expires_in", 720));
        TokenController controller = new TokenController();
        ReflectionTestUtils.setField(controller, "tokenService", tokenService);
        ReflectionTestUtils.setField(controller, "sysLoginService", sysLoginService);

        LoginBody loginBody = new LoginBody();
        loginBody.setUsername("admin");
        loginBody.setPassword("admin123");
        ApiResponse<?> loginResponse = controller.login(loginBody);
        assertThat(loginResponse.getCode()).isEqualTo("000000");
        assertThat(loginResponse.getData()).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> tokenMap = (Map<String, Object>) loginResponse.getData();
        assertThat(tokenMap).containsOnlyKeys("access_token", "expires_in");
        assertThat(tokenMap.get("access_token")).isEqualTo("test-token");
        assertThat(tokenMap.get("expires_in")).isInstanceOf(Number.class);

        RegisterBody registerBody = new RegisterBody();
        registerBody.setUsername("newuser");
        registerBody.setPassword("newuser123");
        assertThat(controller.register(registerBody).getData()).isNull();
        assertThat(REGISTERED_BODIES).hasSize(1);

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        assertThat(controller.logout(request).getData()).isNull();
        assertThat(controller.refresh(request).getData()).isNull();
    }

    // ---------- stub 支撑 ----------

    /**
     * 复现 EDD-MPT {@code ApiResponse<LoginUser>} 响应体（ISO/legacy/epoch 或非法值由调用方注入）。
     */
    private static String loginUserJson(String createTimeJson, String updateTimeJson) {
        return """
                {
                  "code": "000000",
                  "message": "操作成功",
                  "data": {
                    "userid": 1,
                    "username": "admin",
                    "sysUser": {
                      "userId": 1,
                      "userName": "admin",
                      "nickName": "管理员",
                      "password": "%s",
                      "status": "0",
                      "delFlag": "0",
                      "createTime": %s,
                      "updateTime": %s
                    }
                  },
                  "timestamp": 1732878150000
                }
                """.formatted(PASSWORD_HASH, createTimeJson, updateTimeJson);
    }

    private static List<String> messageChain(Throwable throwable) {
        List<String> messages = new ArrayList<>();
        Throwable current = throwable;
        while (current != null) {
            messages.add(String.valueOf(current.getMessage()));
            current = current.getCause();
        }
        return messages;
    }

    private static String capture(HttpExchange exchange, List<String> sink) throws IOException {
        sink.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        return "{\"code\":\"000000\",\"message\":\"操作成功\",\"data\":true,\"timestamp\":1732878150000}";
    }

    private static void respond(HttpExchange exchange, String body) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json;charset=UTF-8");
        exchange.sendResponseHeaders(200, payload.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(payload);
        } finally {
            exchange.close();
        }
    }

    /**
     * 从扁平/嵌套 JSON 文本中取出指定字段的字符串值（仅用于请求体字段断言）。
     */
    private static String extractText(String json, String field) {
        String marker = "\"" + field + "\":\"";
        int start = json.indexOf(marker);
        assertThat(start).as("响应/请求体中应包含字段 %s", field).isGreaterThanOrEqualTo(0);
        int valueStart = start + marker.length();
        int valueEnd = json.indexOf('"', valueStart);
        return json.substring(valueStart, valueEnd);
    }

    /**
     * 测试专用最小上下文：生产 Jackson 装配 + Spring Cloud OpenFeign（真实解码器）+ 真实登录编排。
     */
    @Configuration(proxyBeanMethods = false)
    @ImportAutoConfiguration({
            JacksonAutoConfiguration.class,
            IovJacksonAutoConfiguration.class,
            HttpMessageConvertersAutoConfiguration.class,
            FeignAutoConfiguration.class
    })
    @EnableFeignClients(clients = RemoteUserService.class)
    @Import({EiamJacksonConfig.class, SysLoginService.class, SysPasswordService.class, SysRecordLogService.class,
            net.hwyz.iov.cloud.sec.eiam.service.service.IdentityGuard.class})
    static class TestApplication {

        /**
         * 密码重试存储按 CR 允许隔离：只影响重试计数，不参与 Date 解码与登录编排断言。
         */
        /**
         * RedisService 的 {@code @Autowired} 字段需要容器中存在 RedisTemplate（Mockito mock 也会被
         * Spring 后处理注入），此处仅提供类型占位，不建立真实连接。
         */
        @Bean
        RedisTemplate<Object, Object> redisTemplate() {
            return Mockito.mock(RedisTemplate.class);
        }

        /**
         * 身份目录校验：由真实 IdentityGuard + mock mapper 组成；测试用账号未绑定员工（employeeId 为空）时自动跳过。
         */
        @Bean
        net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamIdentityMapper eiamIdentityMapper() {
            return Mockito.mock(net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamIdentityMapper.class);
        }

        @Bean
        RedisService redisService() {
            RedisService redisService = Mockito.mock(RedisService.class);
            Mockito.when(redisService.hasKey(Mockito.anyString())).thenReturn(false);
            return redisService;
        }

        @Bean
        RemoteLogService remoteLogService() {
            return Mockito.mock(RemoteLogService.class);
        }

        @Bean
        feign.Client feignClient() {
            // 传输层显式使用标准 HttpURLConnection（与本机回环 stub 确定性配合）
            return new feign.Client.Default(null, null);
        }
    }
}
