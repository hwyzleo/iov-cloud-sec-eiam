package net.hwyz.iov.cloud.sec.eiam.service.controller;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import net.hwyz.iov.cloud.framework.security.annotation.RequiresPermissions;
import net.hwyz.iov.cloud.sec.eiam.service.service.IdentityAdminService;
import net.hwyz.iov.cloud.sec.eiam.service.vo.IdentityView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 身份目录管理端点（SEC-EIAM-DSN-CR-002 原地修订·第二次 §13.7）
 * <p>
 * 外部访问路径为网关前缀下的 `/prod-api/auth/identity/**`（网关 `/auth/**` 路由到本服务）。
 * 权限暂复用 MPT 既有权限点：
 * TODO 待 MPT 菜单表登记 `security:identity:list` / `security:identity:edit` 后切换为专用权限点。
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequestMapping("/identity")
public class IdentityAdminController {

    @Autowired
    private IdentityAdminService identityAdminService;

    /**
     * 身份目录分页查询
     */
    @RequiresPermissions("system:user:list")
    @GetMapping("/list")
    public ApiResponse<PageResult<IdentityView>> list(@RequestParam(required = false) String key,
                                                      @RequestParam(required = false) String status,
                                                      @RequestParam(defaultValue = "1") int page,
                                                      @RequestParam(defaultValue = "10") int size) {
        return ApiResponse.ok(identityAdminService.list(key, status, page, size));
    }

    /**
     * 管理员重置密码：一次性明文仅在本响应返回
     */
    @RequiresPermissions("system:user:edit")
    @PostMapping("/{employeeId}/reset-password")
    public ApiResponse<Map<String, Object>> resetPassword(@PathVariable Long employeeId) {
        String plainPassword = identityAdminService.resetPassword(employeeId);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("employeeId", employeeId);
        data.put("password", plainPassword);
        data.put("pwdResetRequired", true);
        data.put("message", "请在本次弹窗内记录并线下告知员工；该密码仅显示一次，员工首次登录后须修改密码");
        log.info("身份目录：重置员工[{}] EIAM 凭据密码", employeeId);
        return ApiResponse.ok(data);
    }

    /**
     * 启用登录账号（清凭据锁定 + 联动 MPT）
     */
    @RequiresPermissions("system:user:edit")
    @PostMapping("/{employeeId}/enable")
    public ApiResponse<Integer> enable(@PathVariable Long employeeId) {
        log.info("身份目录：启用员工[{}]登录账号", employeeId);
        return ApiResponse.ok(identityAdminService.enable(employeeId));
    }

    /**
     * 停用登录账号（联动 MPT，撤销在线会话）
     */
    @RequiresPermissions("system:user:edit")
    @PostMapping("/{employeeId}/disable")
    public ApiResponse<Integer> disable(@PathVariable Long employeeId) {
        log.info("身份目录：停用员工[{}]登录账号", employeeId);
        return ApiResponse.ok(identityAdminService.disable(employeeId));
    }

    /**
     * 解锁账号（清失败计数与锁定时间）
     */
    @RequiresPermissions("system:user:edit")
    @PostMapping("/{employeeId}/unlock")
    public ApiResponse<Void> unlock(@PathVariable Long employeeId) {
        log.info("身份目录：解锁员工[{}]", employeeId);
        identityAdminService.unlock(employeeId);
        return ApiResponse.ok();
    }
}
