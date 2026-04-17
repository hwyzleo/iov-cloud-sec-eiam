package net.hwyz.iov.cloud.sec.eiam.service.service;

import cn.hutool.core.convert.Convert;
import cn.hutool.core.util.StrUtil;
import net.hwyz.iov.cloud.edd.mpt.api.RemoteUserService;
import net.hwyz.iov.cloud.edd.mpt.api.domain.SysUser;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.constant.CacheConstants;
import net.hwyz.iov.cloud.framework.common.constant.SecurityConstants;
import net.hwyz.iov.cloud.framework.common.constant.MptUserConstants;
import net.hwyz.iov.cloud.framework.common.enums.MptUserStatus;
import net.hwyz.iov.cloud.framework.common.exception.ServiceException;
import net.hwyz.iov.cloud.framework.common.util.DateTimeUtil;
import net.hwyz.iov.cloud.framework.common.util.IpUtil;
import net.hwyz.iov.cloud.framework.redis.service.RedisService;
import net.hwyz.iov.cloud.framework.security.util.SecurityUtils;
import net.hwyz.iov.cloud.framework.web.constant.MptConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 登录校验方法
 *
 * @author hwyz_leo
 */
@Service
public class SysLoginService {
    @Autowired
    private RemoteUserService remoteUserService;

    @Autowired
    private SysPasswordService passwordService;

    @Autowired
    private SysRecordLogService recordLogService;

    @Autowired
    private RedisService redisService;

    /**
     * 登录
     */
    public LoginUser login(String username, String password) {
        // 用户名或密码为空 错误
        if (StrUtil.hasBlank(username, password)) {
            recordLogService.recordLogininfor(username, MptConstants.LOGIN_FAIL, "用户/密码必须填写");
            throw new ServiceException("用户/密码必须填写");
        }
        // 密码如果不在指定范围内 错误
        if (password.length() < MptUserConstants.PASSWORD_MIN_LENGTH
                || password.length() > MptUserConstants.PASSWORD_MAX_LENGTH) {
            recordLogService.recordLogininfor(username, MptConstants.LOGIN_FAIL, "用户密码不在指定范围");
            throw new ServiceException("用户密码不在指定范围");
        }
        // 用户名不在指定范围内 错误
        if (username.length() < MptUserConstants.USERNAME_MIN_LENGTH
                || username.length() > MptUserConstants.USERNAME_MAX_LENGTH) {
            recordLogService.recordLogininfor(username, MptConstants.LOGIN_FAIL, "用户名不在指定范围");
            throw new ServiceException("用户名不在指定范围");
        }
        // IP黑名单校验
        String blackStr = Convert.toStr(redisService.getCacheObject(CacheConstants.SYS_LOGIN_BLACKIPLIST));
        if (IpUtil.isMatchedIp(blackStr, IpUtil.getIpAddr())) {
            recordLogService.recordLogininfor(username, MptConstants.LOGIN_FAIL, "很遗憾，访问IP已被列入系统黑名单");
            throw new ServiceException("很遗憾，访问IP已被列入系统黑名单");
        }
        // 查询用户信息
        ApiResponse<LoginUser> userResult = remoteUserService.getUserInfo(username, SecurityConstants.INNER);

        if (!"000000".equals(userResult.getCode())) {
            throw new ServiceException(userResult.getMessage());
        }

        LoginUser userInfo = userResult.getData();
        SysUser user = userResult.getData().getSysUser();
        if (MptUserStatus.DELETED.getCode().equals(user.getDelFlag())) {
            recordLogService.recordLogininfor(username, MptConstants.LOGIN_FAIL, "对不起，您的账号已被删除");
            throw new ServiceException("对不起，您的账号：" + username + " 已被删除");
        }
        if (MptUserStatus.DISABLE.getCode().equals(user.getStatus())) {
            recordLogService.recordLogininfor(username, MptConstants.LOGIN_FAIL, "用户已停用，请联系管理员");
            throw new ServiceException("对不起，您的账号：" + username + " 已停用");
        }
        passwordService.validate(user, password);
        recordLogService.recordLogininfor(username, MptConstants.LOGIN_SUCCESS, "登录成功");
        recordLoginInfo(user.getUserId());
        return userInfo;
    }

    /**
     * 记录登录信息
     *
     * @param userId 用户ID
     */
    public void recordLoginInfo(Long userId) {
        SysUser sysUser = new SysUser();
        sysUser.setUserId(userId);
        // 更新用户登录IP
        sysUser.setLoginIp(IpUtil.getIpAddr());
        // 更新用户登录时间
        sysUser.setLoginDate(DateTimeUtil.getNowDate());
        remoteUserService.recordUserLogin(sysUser, SecurityConstants.INNER);
    }

    public void logout(String loginName) {
        recordLogService.recordLogininfor(loginName, MptConstants.LOGOUT, "退出成功");
    }

    /**
     * 注册
     */
    public void register(String username, String password) {
        // 用户名或密码为空 错误
        if (StrUtil.hasBlank(username, password)) {
            throw new ServiceException("用户/密码必须填写");
        }
        if (username.length() < MptUserConstants.USERNAME_MIN_LENGTH
                || username.length() > MptUserConstants.USERNAME_MAX_LENGTH) {
            throw new ServiceException("账户长度必须在2到20个字符之间");
        }
        if (password.length() < MptUserConstants.PASSWORD_MIN_LENGTH
                || password.length() > MptUserConstants.PASSWORD_MAX_LENGTH) {
            throw new ServiceException("密码长度必须在5到20个字符之间");
        }

        // 注册用户信息
        SysUser sysUser = new SysUser();
        sysUser.setUserName(username);
        sysUser.setNickName(username);
        sysUser.setPassword(SecurityUtils.encryptPassword(password));
        ApiResponse<?> registerResult = remoteUserService.registerUserInfo(sysUser, SecurityConstants.INNER);

        if (!"000000".equals(registerResult.getCode())) {
            throw new ServiceException(registerResult.getMessage());
        }
        recordLogService.recordLogininfor(username, MptConstants.REGISTER, "注册成功");
    }
}