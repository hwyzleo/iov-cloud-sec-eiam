package net.hwyz.iov.cloud.sec.eiam.service.service;

import cn.hutool.core.util.StrUtil;
import net.hwyz.iov.cloud.framework.common.constant.MptSecurityConstants;
import net.hwyz.iov.cloud.framework.common.util.IpUtil;
import net.hwyz.iov.cloud.framework.web.constant.MptConstants;
import net.hwyz.iov.cloud.edd.mpt.api.RemoteLogService;
import net.hwyz.iov.cloud.edd.mpt.api.domain.SysLogininfor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 记录日志方法
 *
 * @author hwyz_leo
 */
@Service
public class SysRecordLogService {
    @Autowired
    private RemoteLogService remoteLogService;

    /**
     * 记录登录信息
     *
     * @param username 用户名
     * @param status   状态
     * @param message  消息内容
     * @return
     */
    public void recordLogininfor(String username, String status, String message) {
        SysLogininfor logininfor = new SysLogininfor();
        logininfor.setUserName(username);
        logininfor.setIpaddr(IpUtil.getIpAddr());
        logininfor.setMsg(message);
        // 日志状态
        if (StrUtil.equalsAny(status, MptConstants.LOGIN_SUCCESS, MptConstants.LOGOUT, MptConstants.REGISTER)) {
            logininfor.setStatus(MptConstants.LOGIN_SUCCESS_STATUS);
        } else if (MptConstants.LOGIN_FAIL.equals(status)) {
            logininfor.setStatus(MptConstants.LOGIN_FAIL_STATUS);
        }
        remoteLogService.saveLogininfor(logininfor, MptSecurityConstants.INNER);
    }
}