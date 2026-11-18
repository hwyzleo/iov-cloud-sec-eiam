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
    MPT_USER_BINDING_MISSING("401007", "该员工尚未开通登录账号，请联系管理员"),

    /**
     * 凭据不存在或未开通（原地修订·第二次）
     */
    CREDENTIAL_NOT_FOUND("401008", "凭据不存在或尚未开通，请联系管理员"),

    /**
     * 密码错误（未达锁定阈值）
     */
    CREDENTIAL_PASSWORD_INCORRECT("401009", "工号或密码错误"),

    /**
     * 连续密码错误导致账号锁定
     */
    CREDENTIAL_ACCOUNT_LOCKED("401010", "密码错误次数过多，账号已锁定，请稍后再试或联系管理员解锁"),

    /**
     * 必须先修改密码（不签发 token/授权码）
     */
    CREDENTIAL_PWD_RESET_REQUIRED("401011", "首次登录或密码已重置，请先修改密码");

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

    /**
     * 按错误码值查找枚举（未匹配返回 null）
     *
     * @param code 错误码值
     * @return 错误码枚举
     */
    public static EiamErrorCode of(String code) {
        for (EiamErrorCode value : values()) {
            if (value.code.equals(code)) {
                return value;
            }
        }
        return null;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
