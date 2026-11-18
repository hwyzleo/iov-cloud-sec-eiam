package net.hwyz.iov.cloud.sec.eiam.service.exception;

import net.hwyz.iov.cloud.sec.eiam.service.enums.EiamErrorCode;

/**
 * EIAM 业务异常（携带 EIAM 错误码）
 * <p>
 * `framework-common` 的 {@code ServiceException} 为 final 且不携带 {@link EiamErrorCode}，
 * 因此新增本异常用于凭据校验等场景，由 {@code EiamExceptionHandler} 统一转换为带业务码的响应；
 * OAuth 登录页自行捕获并渲染可读 HTML。
 *
 * @author hwyz_leo
 */
public class EiamBizException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * EIAM 错误码
     */
    private final EiamErrorCode errorCode;

    public EiamBizException(EiamErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    public EiamBizException(EiamErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public EiamErrorCode getErrorCode() {
        return errorCode;
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
