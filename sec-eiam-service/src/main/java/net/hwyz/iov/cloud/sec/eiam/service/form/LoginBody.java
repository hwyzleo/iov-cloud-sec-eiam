package net.hwyz.iov.cloud.sec.eiam.service.form;

import lombok.Getter;
import lombok.Setter;

/**
 * 用户登录对象
 *
 * @author hwyz_leo
 */
@Getter
@Setter
public class LoginBody {
    /**
     * 用户名
     */
    private String username;

    /**
     * 用户密码
     */
    private String password;
}