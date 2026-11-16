package net.hwyz.iov.cloud.sec.eiam.service.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.hwyz.iov.cloud.edd.mpt.api.domain.SysUser;
import net.hwyz.iov.cloud.framework.web.autoconfigure.IovJacksonAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 生产 mapper 契约测试（SEC-EIAM-DSN-CR-001，TC-001-04 / TC-001-05）。
 * <p>
 * 使用真实 Boot {@link JacksonAutoConfiguration} + framework {@link IovJacksonAutoConfiguration}
 * + {@link EiamJacksonConfig} 构建的生产 {@code ObjectMapper}（含 framework 启动探针校验），
 * 断言真实 {@link SysUser} 字段在继承 {@code @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")} 的
 * 前提下接受全部已批准表示，且写侧仍由 framework 独占。
 *
 * @author hwyz_leo
 * @since 2026-11-16
 */
class EiamJacksonConfigTest {

    private static final ZoneId SHANGHAI = ZoneId.of("Asia/Shanghai");
    private static final Instant SAMPLE = Instant.parse("2024-11-29T10:22:30Z");

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        JacksonAutoConfiguration.class,
                        IovJacksonAutoConfiguration.class))
                .withUserConfiguration(EiamJacksonConfig.class);
    }

    private ApplicationContextRunner isoRunner() {
        return runner().withPropertyValues(
                "iov.web.jackson.date-format=iso",
                "iov.web.jackson.zone-id=Asia/Shanghai");
    }

    // ---------- TC-001-04：生产 mapper 读契约 ----------

    @Test
    void 真实SysUser字段_继承pattern仍接受ISO与legacy与epoch() {
        isoRunner().run(context -> {
            assertThat(context).hasNotFailed();
            ObjectMapper mapper = context.getBean(ObjectMapper.class);

            SysUser fromIsoZ = mapper.readValue(
                    "{\"createTime\":\"2024-11-29T10:22:30.000Z\"}", SysUser.class);
            SysUser fromIsoOffset = mapper.readValue(
                    "{\"updateTime\":\"2024-11-29T18:22:30+08:00\"}", SysUser.class);
            SysUser fromLegacy = mapper.readValue(
                    "{\"createTime\":\"2024-11-29 18:22:30\"}", SysUser.class);
            SysUser fromEpoch = mapper.readValue(
                    "{\"updateTime\":" + SAMPLE.toEpochMilli() + "}", SysUser.class);

            assertThat(fromIsoZ.getCreateTime()).isEqualTo(Date.from(SAMPLE));
            assertThat(fromIsoOffset.getUpdateTime()).isEqualTo(Date.from(SAMPLE));
            assertThat(fromLegacy.getCreateTime()).isEqualTo(Date.from(SAMPLE));
            assertThat(fromEpoch.getUpdateTime()).isEqualTo(Date.from(SAMPLE));
        });
    }

    @Test
    void eiam读模块位于framework读模块之后且framework读能力保留() {
        isoRunner().run(context -> {
            assertThat(context).hasNotFailed();
            ObjectMapper mapper = context.getBean(ObjectMapper.class);

            List<Object> moduleIds = new ArrayList<>(mapper.getRegisteredModuleIds());
            assertThat(moduleIds).contains("iov-java-time-read", "eiam-date-read");
            assertThat(moduleIds.indexOf("iov-java-time-read"))
                    .isLessThan(moduleIds.indexOf("eiam-date-read"));

            // framework java.time 读模块仍生效（ISO 与旧数字双读）
            assertThat(mapper.readValue("\"2024-11-29T10:22:30.000Z\"", Instant.class))
                    .isEqualTo(SAMPLE);
            assertThat(mapper.readValue(String.valueOf(SAMPLE.getEpochSecond()), Instant.class))
                    .isEqualTo(SAMPLE);
        });
    }

    @Test
    void 未注册eiam读模块_ISO无法解码_复现原缺陷() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        JacksonAutoConfiguration.class,
                        IovJacksonAutoConfiguration.class))
                .withPropertyValues(
                        "iov.web.jackson.date-format=iso",
                        "iov.web.jackson.zone-id=Asia/Shanghai")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    ObjectMapper mapper = context.getBean(ObjectMapper.class);
                    // 仅 framework（无 Date 读模块）时，字段 pattern 使 ISO 字符串解码失败——即 CR 记录的故障
                    assertThatThrownBy(() -> mapper.readValue(
                            "{\"createTime\":\"2024-11-29T10:22:30.000Z\"}", SysUser.class))
                            .isInstanceOf(Exception.class);
                });
    }

    // ---------- TC-001-05：写侧回归归 framework 所有 ----------

    @Test
    void iso模式_Date写出仍为UTC三位毫秒Z() {
        isoRunner().run(context -> {
            assertThat(context).hasNotFailed();
            ObjectMapper mapper = context.getBean(ObjectMapper.class);

            assertThat(mapper.writeValueAsString(Date.from(SAMPLE)))
                    .isEqualTo("\"2024-11-29T10:22:30.000Z\"");

            // 字段级 legacy pattern 不得改变 ISO 写契约（写模块归 framework）
            SysUser sysUser = new SysUser();
            sysUser.setCreateTime(Date.from(SAMPLE));
            sysUser.setUpdateTime(Date.from(SAMPLE));
            JsonNode node = mapper.valueToTree(sysUser);
            assertThat(node.get("createTime").asText()).isEqualTo("2024-11-29T10:22:30.000Z");
            assertThat(node.get("updateTime").asText()).isEqualTo("2024-11-29T10:22:30.000Z");

            // framework LocalDateTime 写契约不变（按显式 zone-id 换算为瞬时）
            assertThat(mapper.writeValueAsString(LocalDateTime.parse("2024-11-29T18:22:30")))
                    .isEqualTo("\"2024-11-29T10:22:30.000Z\"");
        });
    }

    @Test
    void epochMillis模式_Date写仍归framework且EIAM读模块不夺写权() {
        runner()
                .withPropertyValues(
                        "iov.web.jackson.date-format=epoch-millis",
                        "iov.web.jackson.zone-id=Asia/Shanghai")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    ObjectMapper mapper = context.getBean(ObjectMapper.class);

                    JsonNode node = mapper.valueToTree(Date.from(SAMPLE));
                    assertThat(node.isIntegralNumber()).isTrue();
                    assertThat(node.longValue()).isEqualTo(SAMPLE.toEpochMilli());

                    // 兼容读不受写模式影响：ISO / legacy / epoch 仍可读
                    assertThat(mapper.readValue("\"2024-11-29T10:22:30.000Z\"", Date.class))
                            .isEqualTo(Date.from(SAMPLE));
                    assertThat(mapper.readValue("\"2024-11-29 18:22:30\"", Date.class))
                            .isEqualTo(Date.from(SAMPLE));
                });
    }
}
