package net.hwyz.iov.cloud.sec.eiam.service.oauth;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import net.hwyz.iov.cloud.framework.common.exception.ServiceException;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper.EiamOauthClientMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamOauthClientPo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Arrays;

/**
 * OIDC 客户端校验（SEC-EIAM-DSN-CR-002 §10.4）
 * <p>
 * 回调地址采用**精确匹配**，不支持通配；客户端不存在或禁用时拒绝授权且不跳转。
 *
 * @author hwyz_leo
 */
@Component
public class OAuthClientValidator {

    @Autowired
    private EiamOauthClientMapper oauthClientMapper;

    /**
     * 校验客户端与回调地址
     *
     * @param clientId    客户端ID
     * @param redirectUri 回调地址
     * @return 客户端
     */
    public EiamOauthClientPo validate(String clientId, String redirectUri) {
        if (!StringUtils.hasText(clientId)) {
            throw new ServiceException(EiamErrorCode.SSO_CLIENT_INVALID.getMessage());
        }
        EiamOauthClientPo client = oauthClientMapper.selectOne(Wrappers.<EiamOauthClientPo>lambdaQuery()
                .eq(EiamOauthClientPo::getClientId, clientId)
                .last("limit 1"));
        if (client == null || client.getEnabled() == null || client.getEnabled() != 1) {
            throw new ServiceException(EiamErrorCode.SSO_CLIENT_INVALID.getMessage());
        }
        if (!StringUtils.hasText(redirectUri) || !matchesRedirect(client.getRedirectUris(), redirectUri)) {
            throw new ServiceException(EiamErrorCode.SSO_REDIRECT_URI_INVALID.getMessage());
        }
        return client;
    }

    private boolean matchesRedirect(String whitelist, String redirectUri) {
        if (!StringUtils.hasText(whitelist)) {
            return false;
        }
        return Arrays.stream(whitelist.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .anyMatch(uri -> uri.equals(redirectUri));
    }
}
