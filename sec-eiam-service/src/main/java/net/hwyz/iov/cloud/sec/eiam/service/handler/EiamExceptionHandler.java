package net.hwyz.iov.cloud.sec.eiam.service.handler;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.sec.eiam.service.exception.EiamBizException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * EIAM 业务异常处理（SEC-EIAM-DSN-CR-002 原地修订·第二次）
 * <p>
 * 将 {@link EiamBizException} 转为携带 EIAM 业务错误码的统一响应；OAuth 登录页
 * （HTML 表单）在控制器内自行捕获并渲染可读页面，不经过本处理器。
 *
 * @author hwyz_leo
 */
@Slf4j
@RestControllerAdvice
public class EiamExceptionHandler {

    @ExceptionHandler(EiamBizException.class)
    public ApiResponse<Void> handleEiamBizException(EiamBizException e) {
        log.warn("EIAM 业务异常：code={}, message={}", e.getErrorCode().getCode(), e.getMessage());
        return ApiResponse.fail(e.getErrorCode(), e.getMessage());
    }
}
