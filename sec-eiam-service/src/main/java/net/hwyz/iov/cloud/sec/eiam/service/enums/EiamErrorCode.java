package net.hwyz.iov.cloud.sec.eiam.service.enums;

import net.hwyz.iov.cloud.framework.common.exception.ErrorCode;

/**
 * EIAM 认证与身份目录错误码（SEC-EIAM-DSN-CR-002 §10.6）
 *
 * @author hwyz_leo
 */
public enum EiamErrorCode implements ErrorCode {

    /**
     * 客户端不存在或已禁用
     */
    SSO_CLIENT_INVALID("401001", "客户端不存在或已禁用"),

    /**
     * 回调地址不在白名单
     */
    SSO_REDIRECT_URI_INVALID("401002", "回调地址不在白名单"),

    /**
     * 授权码无效、过期或已使用
     */
    SSO_CODE_INVALID("401003", "授权码无效、已过期或已被使用"),

    /**
     * 授权码与客户端/回调不匹配
     */
    SSO_CODE_CLIENT_MISMATCH("401004", "授权码与客户端或回调地址不匹配"),

    /**
     * 目录中不存在该员工身份
     */
    IDENTITY_NOT_FOUND("401005", "目录中不存在该员工身份"),

    /**
     * 员工已停用、离职或删除
     */
    IDENTITY_NOT_ACTIVE("401006", "员工已停用、离职或删除，禁止登录"),

    /**
     * MPT 侧未绑定该员工的账号
     */
    MPT_USER_BINDING_MISSING("401007", "该员工尚未开通登录账号，请联系管理员");

    private final String code;

    private final String message;

    EiamErrorCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

    @Override
    public String getCode() {
        return code;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
