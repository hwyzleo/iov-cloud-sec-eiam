package net.hwyz.iov.cloud.sec.eiam.service.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;

import java.io.IOException;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.Date;

/**
 * 过渡性 {@link java.util.Date} 反序列化器（SEC-EIAM-DSN-CR-001，RD-001-1/3/4/6）。
 * <p>
 * 非 contextual：不实现 {@link com.fasterxml.jackson.databind.deser.ContextualDeserializer}，
 * 因此不会从字段级 {@code @JsonFormat(pattern = ...)} 派生 {@code DateFormat}——
 * EDD-MPT 的 {@code BaseEntity.createTime/updateTime} 继承的 legacy pattern 不得缩窄读能力。
 * <p>
 * 输入矩阵：
 * <ul>
 *   <li>带 {@code Z} 或数字 offset 的 ISO-8601 字符串：offset 感知解析为瞬时（小数秒精度随
 *       {@link java.time} ISO 解析器，不要求恰好三位）；</li>
 *   <li>严格 {@code uuuu-MM-dd HH:mm:ss} 墙上时间字符串（契约名仍为 {@code yyyy-MM-dd HH:mm:ss}）：
 *       应用显式 {@code iov.web.jackson.zone-id} 换算为瞬时；未配置时区时 fail-closed；</li>
 *   <li>整型数字：有符号 64 位 epoch 毫秒，不套用字段 pattern 与时区；0 与合法负值照常接受；</li>
 *   <li>JSON {@code null}：由 Jackson 置空处理，不转换为 {@code new Date(0)}。</li>
 * </ul>
 * 拒绝矩阵（fail-closed，不做无依据猜测）：空/空白串、非法 ISO、无 offset 且不匹配精确 legacy
 * 格式的类 ISO 字符串、非法日历值、小数、数字字符串、数组、对象、布尔值及 64 位溢出整数。
 *
 * @author hwyz_leo
 * @since 2026-11-16
 */
public class EiamDateDeserializer extends JsonDeserializer<Date> {

    /**
     * legacy 墙上时间格式：严格解析（{@link ResolverStyle#STRICT} 禁止宽容日历进位），
     * 使用 {@code uuuu} 以免 STRICT 下的 era 语义问题。
     */
    static final DateTimeFormatter LEGACY_WALL_CLOCK =
            DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss").withResolverStyle(ResolverStyle.STRICT);

    private final ZoneId zoneId;

    public EiamDateDeserializer(ZoneId zoneId) {
        this.zoneId = zoneId;
    }

    @Override
    public Date deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonToken token = p.currentToken();
        if (token == JsonToken.VALUE_STRING) {
            return Date.from(parseText(p));
        }
        if (token == JsonToken.VALUE_NUMBER_INT) {
            return new Date(readEpochMillis(p));
        }
        if (token == JsonToken.VALUE_NUMBER_FLOAT) {
            throw JsonMappingException.from(p, "Date 拒绝小数时间戳（秒小数/亚毫秒），默认不做无依据截断");
        }
        throw JsonMappingException.from(p,
                "Date 仅支持带 offset 的 ISO-8601 字符串、严格 yyyy-MM-dd HH:mm:ss 墙上时间或 epoch 毫秒整数");
    }

    /**
     * 字符串输入：ISO-8601（含 offset）优先，其次严格 legacy 墙上时间；其余一律拒绝。
     */
    private Instant parseText(JsonParser p) throws IOException {
        String text = p.getText().trim();
        if (text.isEmpty()) {
            throw JsonMappingException.from(p, "Date 不接受空字符串或空白字符串");
        }
        try {
            return OffsetDateTime.parse(text).toInstant();
        } catch (DateTimeParseException ignored) {
            // 无 offset 的字符串不是瞬时，可能是 legacy 墙上时间：继续严格匹配
        }
        LocalDateTime wallClock;
        try {
            wallClock = LocalDateTime.parse(text, LEGACY_WALL_CLOCK);
        } catch (DateTimeParseException e) {
            throw JsonMappingException.from(p,
                    "Date 仅支持带 offset 的 ISO-8601 字符串、严格 yyyy-MM-dd HH:mm:ss 墙上时间或 epoch 毫秒整数: "
                            + text, e);
        }
        if (zoneId == null) {
            throw JsonMappingException.from(p,
                    "legacy 墙上时间 Date 入站需要显式 iov.web.jackson.zone-id（禁止使用 JVM 默认时区猜测业务语义）");
        }
        try {
            return wallClock.atZone(zoneId).toInstant();
        } catch (DateTimeException e) {
            throw JsonMappingException.from(p, "legacy 墙上时间在配置时区下无法换算为瞬时: " + text, e);
        }
    }

    /**
     * 整型输入：有符号 64 位 epoch 毫秒；溢出交由 Jackson 的数值强制转换失败暴露。
     */
    private long readEpochMillis(JsonParser p) throws JsonMappingException {
        try {
            return p.getLongValue();
        } catch (IOException e) {
            throw JsonMappingException.from(p,
                    "Date epoch 毫秒值无法表示为有符号 64 位整数（溢出）", e);
        }
    }
}
