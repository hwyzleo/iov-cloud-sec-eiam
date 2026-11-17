package net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * OIDC 客户端（SEC-EIAM-DSN-CR-002）
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@TableName("eiam_oauth_client")
public class EiamOauthClientPo {

    /**
     * 客户端ID
     */
    @TableId("client_id")
    private String clientId;

    /**
     * 客户端名称
     */
    private String clientName;

    /**
     * 回调地址白名单（逗号分隔，精确匹配）
     */
    private String redirectUris;

    /**
     * 是否启用
     */
    private Integer enabled;

}
