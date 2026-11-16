package net.hwyz.iov.cloud.sec.eiam.service.config;

import net.hwyz.iov.cloud.framework.web.jackson.JacksonProperties;
import net.hwyz.iov.cloud.sec.eiam.service.jackson.EiamDateReadModule;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

/**
 * EIAM Jackson 过渡配置（SEC-EIAM-DSN-CR-001，RD-001-2/3/5/8）。
 * <p>
 * 在 framework {@code IovJacksonAutoConfiguration}（{@link Ordered#HIGHEST_PRECEDENCE}，注册
 * {@code IovJavaTimeReadModule} 与配置的写模块）之后，以 {@link Ordered#LOWEST_PRECEDENCE} 追加
 * 一个 {@code postConfigurer}，只向同一个 Spring {@code ObjectMapper} 补充缺失的
 * {@code java.util.Date} 读模块：
 * <ul>
 *   <li>不新建手工 mapper、不替换 framework customizer、不使用 Feign 专用 mapper——
 *       MVC 与 Spring OpenFeign 继续共用该生产 mapper；</li>
 *   <li>不注册 Date 序列化器、不修改 {@code iov.web.jackson.date-format}——写出仍由 framework 独占；</li>
 *   <li>时区复用 framework {@link JacksonProperties#getZoneId()}，不提供本地默认值，
 *       禁止 {@code ZoneId.systemDefault()} 与新增 EIAM 时区键。</li>
 * </ul>
 * TODO(SEC-EIAM-DSN-CR-001 RD-001-8)：framework-web 提供同等 Date 读模块后删除本配置。
 *
 * @author hwyz_leo
 * @since 2026-11-16
 */
@Configuration(proxyBeanMethods = false)
public class EiamJacksonConfig {

    /**
     * EIAM 最低优先级的 builder customizer：framework 之后注册 Date 读模块。
     * <p>
     * 只通过 {@code postConfigurer} 追加模块，不动 {@code modulesToInstall} 与序列化器，
     * 保留 framework 的 {@code java.time} 读模块、写模块及 Boot 的 JavaTimeModule 自动发现。
     */
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    public Jackson2ObjectMapperBuilderCustomizer eiamDateReadJacksonCustomizer(JacksonProperties properties) {
        return builder -> builder.postConfigurer(objectMapper ->
                objectMapper.registerModule(new EiamDateReadModule(properties.getZoneId())));
    }
}
