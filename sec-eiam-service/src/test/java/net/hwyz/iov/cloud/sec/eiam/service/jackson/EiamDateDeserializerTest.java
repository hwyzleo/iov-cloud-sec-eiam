package net.hwyz.iov.cloud.sec.eiam.service.jackson;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.TimeZone;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * EIAM 过渡 Date 读模块单测（SEC-EIAM-DSN-CR-001，TC-001-01 / TC-001-02 / TC-001-03）。
 * <p>
 * 断言对象是 {@link EiamDateReadModule} 注册后的反序列化行为本身：输入矩阵、拒绝矩阵、
 * 非 contextual（不受字段 {@code @JsonFormat} 缩窄）与 JVM 默认时区独立性。
 *
 * @author hwyz_leo
 * @since 2026-11-16
 */
class EiamDateDeserializerTest {

    private static final ZoneId SHANGHAI = ZoneId.of("Asia/Shanghai");
    /** 2024-11-29T10:22:30Z == 2024-11-29T18:22:30+08:00 == Asia/Shanghai 墙上时间 2024-11-29 18:22:30 */
    private static final Instant SAMPLE = Instant.parse("2024-11-29T10:22:30Z");
    private static final TimeZone ORIGINAL_JVM_ZONE = TimeZone.getDefault();

    @AfterEach
    void restoreJvmZone() {
        TimeZone.setDefault(ORIGINAL_JVM_ZONE);
    }

    private static ObjectMapper mapper(ZoneId zoneId) {
        return new ObjectMapper().registerModule(new EiamDateReadModule(zoneId));
    }

    private static Date read(ZoneId zoneId, String json) throws Exception {
        return mapper(zoneId).readValue(json, Date.class);
    }

    // ---------- TC-001-01：合法输入矩阵 ----------

    @Test
    void iso带Z_解析为同一瞬时() throws Exception {
        assertThat(read(SHANGHAI, "\"2024-11-29T10:22:30Z\""))
                .isEqualTo(Date.from(SAMPLE));
        assertThat(read(SHANGHAI, "\"2024-11-29T10:22:30.000Z\""))
                .isEqualTo(Date.from(SAMPLE));
    }

    @Test
    void iso带正负offset_按offset解析而非业务时区() throws Exception {
        assertThat(read(SHANGHAI, "\"2024-11-29T18:22:30+08:00\""))
                .isEqualTo(Date.from(SAMPLE));
        assertThat(read(SHANGHAI, "\"2024-11-29T05:22:30-05:00\""))
                .isEqualTo(Date.from(SAMPLE));
    }

    @Test
    void iso小数秒_不要求恰好三位() throws Exception {
        assertThat(read(SHANGHAI, "\"2024-11-29T10:22:30.5Z\""))
                .isEqualTo(Date.from(Instant.parse("2024-11-29T10:22:30.500Z")));
        assertThat(read(SHANGHAI, "\"2024-11-29T10:22:30.123456789Z\""))
                .isEqualTo(Date.from(Instant.parse("2024-11-29T10:22:30.123Z")));
    }

    @Test
    void legacy墙上时间_按配置时区换算为瞬时() throws Exception {
        assertThat(read(SHANGHAI, "\"2024-11-29 18:22:30\""))
                .isEqualTo(Date.from(SAMPLE));
    }

    @Test
    void epoch毫秒整数_直接构造且不套用时区() throws Exception {
        long millis = SAMPLE.toEpochMilli();
        assertThat(read(SHANGHAI, String.valueOf(millis)))
                .isEqualTo(Date.from(SAMPLE));
        // 未配置时区时数字输入仍可用（数字不携带业务时区语义）
        assertThat(read(null, String.valueOf(millis)))
                .isEqualTo(Date.from(SAMPLE));
    }

    @Test
    void epoch零与合法负值_照常接受() throws Exception {
        assertThat(read(SHANGHAI, "0")).isEqualTo(new Date(0L));
        assertThat(read(SHANGHAI, "-1000")).isEqualTo(new Date(-1000L));
    }

    @Test
    void jsonNull_保持null() throws Exception {
        assertThat(read(SHANGHAI, "null")).isNull();
        assertThat(mapper(SHANGHAI).readValue("{\"time\":null}", Holder.class).getTime()).isNull();
    }

    // ---------- TC-001-02：拒绝矩阵 ----------

    @ParameterizedTest
    @ValueSource(strings = {
            "\"\"",
            "\"   \"",
            "\"2024-11-29T10:22:30\"",
            "\"2024-11-29T10:22:30.000\"",
            "\"2024-13-01T10:22:30Z\"",
            "\"2024-02-30T10:22:30Z\"",
            "\"2024-02-30 10:22:30\"",
            "\"2024-11-29 18:22:30.123\"",
            "\"2024-11-29 18:22\"",
            "\"1732878150000\"",
            "\"29/11/2024 18:22:30\"",
            "\"2024-11-29T18:22:30+25:00\""
    })
    void 非法字符串_拒绝(String json) {
        assertThatThrownBy(() -> read(SHANGHAI, json)).isInstanceOf(Exception.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"1.5", "-0.5", "1e3"})
    void 小数时间戳_拒绝(String json) {
        assertThatThrownBy(() -> read(SHANGHAI, json)).isInstanceOf(Exception.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "false", "[]", "[1]", "{}", "{\"time\":1}"})
    void 布尔数组对象_拒绝(String json) {
        assertThatThrownBy(() -> read(SHANGHAI, json)).isInstanceOf(Exception.class);
    }

    @Test
    void 六十四位溢出整数_拒绝() {
        assertThatThrownBy(() -> read(SHANGHAI, "99999999999999999999"))
                .isInstanceOf(Exception.class);
    }

    // ---------- TC-001-03：JVM 默认时区独立 / 缺时区 fail-closed ----------

    @Test
    void 不同JVM默认时区下_legacy解析得到相同瞬时() throws Exception {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        Date fromUtcJvm = read(SHANGHAI, "\"2024-11-29 18:22:30\"");
        TimeZone.setDefault(TimeZone.getTimeZone("America/New_York"));
        Date fromNewYorkJvm = read(SHANGHAI, "\"2024-11-29 18:22:30\"");

        assertThat(fromUtcJvm).isEqualTo(Date.from(SAMPLE));
        assertThat(fromNewYorkJvm).isEqualTo(Date.from(SAMPLE));
        assertThat(fromNewYorkJvm).isEqualTo(fromUtcJvm);
    }

    @Test
    void 缺少配置时区_legacy失败但ISO仍可用() throws Exception {
        assertThatThrownBy(() -> read(null, "\"2024-11-29 18:22:30\""))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("zone-id");
        assertThat(read(null, "\"2024-11-29T10:22:30Z\""))
                .isEqualTo(Date.from(SAMPLE));
    }

    // ---------- 非 contextual：字段 pattern 不得缩窄读能力 ----------

    @Test
    void 字段级JsonFormat_不缩窄读能力() throws Exception {
        ObjectMapper mapper = mapper(SHANGHAI);
        // legacy pattern 声明的字段仍接受 ISO / epoch 毫秒
        Holder fromIso = mapper.readValue("{\"time\":\"2024-11-29T10:22:30.000Z\"}", Holder.class);
        Holder fromEpoch = mapper.readValue("{\"time\":" + SAMPLE.toEpochMilli() + "}", Holder.class);
        Holder fromLegacy = mapper.readValue("{\"time\":\"2024-11-29 18:22:30\"}", Holder.class);

        assertThat(fromIso.getTime()).isEqualTo(Date.from(SAMPLE));
        assertThat(fromEpoch.getTime()).isEqualTo(Date.from(SAMPLE));
        assertThat(fromLegacy.getTime()).isEqualTo(Date.from(SAMPLE));
    }

    /**
     * 与 EDD-MPT {@code BaseEntity} 相同的字段注解形态（lexical pattern 仍为 legacy）。
     */
    static class Holder {
        @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
        private Date time;

        Date getTime() {
            return time;
        }

        @SuppressWarnings("unused")
        public void setTime(Date time) {
            this.time = time;
        }
    }
}
