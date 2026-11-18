package net.hwyz.iov.cloud.sec.eiam.service.migration;

import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 凭据契约测试（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.11）。
 * <p>
 * 断言 Flyway V3 迁移文本与 EIAM 凭据错误码枚举，防止 SQL 与代码脱节。
 *
 * @author hwyz_leo
 * @since 2026-11-18
 */
class EiamCredentialContractTest {

    @Test
    @DisplayName("V3 迁移创建 eiam_credential 且包含全部约定列")
    void v3MigrationDefinesCredentialTable() throws IOException {
        String sql = readClasspath("db/migration/V3__eiam_credential.sql");

        assertTrue(sql.contains("CREATE TABLE IF NOT EXISTS `eiam_credential`"), sql);
        assertTrue(sql.contains("PRIMARY KEY (`uid`)"), sql);
        for (String column : List.of("`uid`", "`password_hash`", "`pwd_reset_required`", "`failed_count`",
                "`locked_until`", "`last_change_time`", "`create_time`", "`modify_time`")) {
            assertTrue(sql.contains(column), "V3 缺少列：" + column);
        }
        assertTrue(sql.contains("VARCHAR(100)"), "password_hash 必须容纳 BCrypt 哈希（60 字符）");
        assertTrue(sql.contains("idx_locked_until"), "锁定查询需要索引");
    }

    @Test
    @DisplayName("错误码：401001～401011 连续且唯一，凭据错误码语义固定")
    void errorCodesAreContiguousAndUnique() {
        List<String> expectedCodes = List.of("401001", "401002", "401003", "401004", "401005", "401006",
                "401007", "401008", "401009", "401010", "401011");
        List<String> actualCodes = Arrays.stream(EiamErrorCode.values())
                .map(EiamErrorCode::getCode)
                .toList();

        assertEquals(expectedCodes, actualCodes, "错误码必须保持既有 401001～401007 并追加 401008～401011");
        assertEquals(expectedCodes.size(), actualCodes.stream().distinct().count(), "错误码不得重复");

        assertEquals(EiamErrorCode.CREDENTIAL_NOT_FOUND, EiamErrorCode.of("401008"));
        assertEquals(EiamErrorCode.CREDENTIAL_PASSWORD_INCORRECT, EiamErrorCode.of("401009"));
        assertEquals(EiamErrorCode.CREDENTIAL_ACCOUNT_LOCKED, EiamErrorCode.of("401010"));
        assertEquals(EiamErrorCode.CREDENTIAL_PWD_RESET_REQUIRED, EiamErrorCode.of("401011"));
    }

    private String readClasspath(String path) throws IOException {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(path)) {
            assertNotNull(input, "找不到 classpath 资源：" + path);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
