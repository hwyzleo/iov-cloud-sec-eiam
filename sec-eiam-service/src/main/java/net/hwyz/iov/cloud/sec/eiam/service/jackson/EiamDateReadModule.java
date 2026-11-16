package net.hwyz.iov.cloud.sec.eiam.service.jackson;

import com.fasterxml.jackson.databind.module.SimpleModule;

import java.time.ZoneId;
import java.util.Date;

/**
 * EIAM 过渡性 {@code java.util.Date} 兼容读模块（SEC-EIAM-DSN-CR-001，RD-001-1/5/8）。
 * <p>
 * 只注册 {@link Date} 反序列化器，<b>不注册任何序列化器</b>：写出形态继续由 framework
 * {@code iov.web.jackson.date-format} 决定的写模块独占（写单一、读兼容）。
 * <p>
 * TODO(SEC-EIAM-DSN-CR-001 RD-001-8)：framework-web 提供同等的 {@code java.util.Date} 读模块后，
 * 删除本模块、{@link EiamDateDeserializer} 及其注册顺序测试，并另立 EIAM 清理 CR 验证不存在
 * 重复反序列化器。EIAM 本地实现不是共享制品，不得被隐式复制到其他服务。
 *
 * @author hwyz_leo
 * @since 2026-11-16
 */
public class EiamDateReadModule extends SimpleModule {

    public EiamDateReadModule(ZoneId zoneId) {
        super("eiam-date-read");
        addDeserializer(Date.class, new EiamDateDeserializer(zoneId));
    }
}
