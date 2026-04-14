package net.hwyz.iov.cloud.sec.eiam.service.controller;

import cn.hutool.core.util.ObjUtil;
import cn.hutool.core.util.StrUtil;
import jakarta.servlet.http.HttpServletRequest;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.util.JwtUtil;
import net.hwyz.iov.cloud.framework.security.auth.AuthUtil;
import net.hwyz.iov.cloud.framework.security.service.TokenService;
import net.hwyz.iov.cloud.framework.security.util.SecurityUtils;
import net.hwyz.iov.cloud.sec.eiam.service.form.LoginBody;
import net.hwyz.iov.cloud.sec.eiam.service.form.RegisterBody;
import net.hwyz.iov.cloud.sec.eiam.service.service.SysLoginService;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * token 控制
 *
 * @author hwyz_leo
 */
@RestController
public class TokenController {
    @Autowired
    private TokenService tokenService;

    @Autowired
    private SysLoginService sysLoginService;

    @PostMapping("login")
    public ApiResponse<?> login(@RequestBody LoginBody form) {
        // 用户登录
        LoginUser userInfo = sysLoginService.login(form.getUsername(), form.getPassword());
        // 获取登录token
        return ApiResponse.ok(tokenService.createToken(userInfo));
    }

    @DeleteMapping("logout")
    public ApiResponse<?> logout(HttpServletRequest request) {
        String token = SecurityUtils.getToken(request);
        if (StrUtil.isNotEmpty(token)) {
            String username = JwtUtil.getUserName(token);
            // 删除用户缓存记录
            AuthUtil.logoutByToken(token);
            // 记录用户退出日志
            sysLoginService.logout(username);
        }
        return ApiResponse.ok();
    }

    @PostMapping("refresh")
    public ApiResponse<?> refresh(HttpServletRequest request) {
        LoginUser loginUser = tokenService.getLoginUser(request);
        if (ObjUtil.isNotNull(loginUser)) {
            // 刷新令牌有效期
            tokenService.refreshToken(loginUser);
            return ApiResponse.ok();
        }
        return ApiResponse.ok();
    }

    @PostMapping("register")
    public ApiResponse<?> register(@RequestBody RegisterBody registerBody) {
        // 用户注册
        sysLoginService.register(registerBody.getUsername(), registerBody.getPassword());
        return ApiResponse.ok();
    }
}