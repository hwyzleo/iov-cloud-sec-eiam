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
import java.util.regex.Pattern;

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

    /**
     * 回调地址匹配：白名单项支持 `*` 通配（如 `http://*&#47;sso/callback`、`https://admin.example.com/*`）。
     * 生产环境建议收敛为精确地址，避免任意主机回调（开放重定向风险）。
     */
    private boolean matchesRedirect(String whitelist, String redirectUri) {
        if (!StringUtils.hasText(whitelist)) {
            return false;
        }
        return Arrays.stream(whitelist.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .anyMatch(uri -> uri.equals(redirectUri) || globMatches(uri, redirectUri));
    }

    private boolean globMatches(String pattern, String value) {
        if (!pattern.contains("*")) {
            return false;
        }
        StringBuilder regex = new StringBuilder("^");
        for (char c : pattern.toCharArray()) {
            if (c == '*') {
                regex.append(".*");
            } else {
                regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        regex.append("$");
        return value.matches(regex.toString());
    }
}
