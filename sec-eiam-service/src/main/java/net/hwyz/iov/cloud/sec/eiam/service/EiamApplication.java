package net.hwyz.iov.cloud.sec.eiam.service;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.annotation.EnableCustomFeignClients;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

/**
 * 认证授权中心
 *
 * @author hwyz_leo
 */
@Slf4j
@EnableCustomFeignClients
@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class EiamApplication {
    public static void main(String[] args) {
        System.setProperty("nacos.logging.default.config.enabled", "false");
        SpringApplication.run(EiamApplication.class, args);
        logger.info("应用启动成功");
    }
}