package net.hwyz.iov.cloud.sec.eiam.service.oauth;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.mpt.api.constant.SecurityConstants;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.exception.ServiceException;
import net.hwyz.iov.cloud.framework.security.service.TokenService;
import net.hwyz.iov.cloud.sec.eiam.service.client.MptUserBindingClient;
import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;
import net.hwyz.iov.cloud.sec.eiam.service.service.IdentityGuard;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * OIDC 授权码换取平台令牌（SEC-EIAM-DSN-CR-002 / US-027）
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
public class OAuthService {

    @Autowired
    private AuthorizationCodeStore authorizationCodeStore;

    @Autowired
    private OAuthClientValidator clientValidator;

    @Autowired
    private MptUserBindingClient mptUserBindingClient;

    @Autowired
    private IdentityGuard identityGuard;

    @Autowired
    private TokenService tokenService;

    /**
     * 用授权码换取平台令牌
     *
     * @param code        授权码
     * @param clientId    客户端ID
     * @param redirectUri 回调地址
     * @return 令牌响应
     */
    public Map<String, Object> exchange(String code, String clientId, String redirectUri) {
        AuthorizationCodeStore.AuthorizationCode authorizationCode = authorizationCodeStore.consume(code);
        if (authorizationCode == null) {
            throw new ServiceException(EiamErrorCode.SSO_CODE_INVALID.getMessage());
        }
        if (!authorizationCode.getClientId().equals(clientId)
                || !authorizationCode.getRedirectUri().equals(redirectUri)) {
            throw new ServiceException(EiamErrorCode.SSO_CODE_CLIENT_MISMATCH.getMessage());
        }
        clientValidator.validate(clientId, redirectUri);

        Long employeeId = authorizationCode.getEmployeeId();
        identityGuard.assertLoginAllowed(employeeId);

        ApiResponse<LoginUser> response = mptUserBindingClient.getUserByEmployeeId(employeeId, SecurityConstants.INNER);
        if (response == null) {
            throw new ServiceException(EiamErrorCode.MPT_USER_BINDING_MISSING.getMessage());
        }
        if (!"000000".equals(response.getCode())) {
            if ("100101".equals(response.getCode())) {
                throw new ServiceException(EiamErrorCode.MPT_USER_BINDING_MISSING.getMessage());
            }
            if ("100103".equals(response.getCode())) {
                throw new ServiceException(EiamErrorCode.IDENTITY_NOT_ACTIVE.getMessage());
            }
            throw new ServiceException(response.getMessage());
        }
        LoginUser loginUser = response.getData();
        if (loginUser == null) {
            throw new ServiceException(EiamErrorCode.MPT_USER_BINDING_MISSING.getMessage());
        }
        loginUser.setEmployeeId(employeeId);

        Map<String, Object> token = tokenService.createToken(loginUser);
        Map<String, Object> result = new HashMap<>(token);
        result.put("token_type", "Bearer");
        result.put("employeeId", employeeId);
        result.put("userName", loginUser.getUsername());
        log.info("单点登录成功：clientId={}, employeeId={}, userId={}", clientId, employeeId, loginUser.getUserid());
        return result;
    }
}
