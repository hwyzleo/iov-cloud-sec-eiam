package net.hwyz.iov.cloud.sec.eiam.service.client;

import net.hwyz.iov.cloud.edd.mpt.api.constant.SecurityConstants;
import net.hwyz.iov.cloud.edd.mpt.api.domain.SysUser;
import net.hwyz.iov.cloud.edd.mpt.api.model.LoginUser;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * MPT 内部契约客户端（SEC-EIAM-DSN-CR-002）
 * <p>
 * 对应 EDD-MPT-DSN-CR-002 提供的内部端点：按员工解析登录用户、幂等开通账号、按员工停用账号。
 * 均要求框架内部来源请求头（`from-source: inner`）。
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "mptUserBindingClient", value = ServiceNameConstants.EDD_MPT, path = "/user")
public interface MptUserBindingClient {

    /**
     * 按员工ID获取登录用户
     *
     * @param employeeId ORG 员工ID
     * @param source     请求来源（inner）
     * @return 登录用户
     */
    @GetMapping("/info/by-employee/{employeeId}")
    ApiResponse<LoginUser> getUserByEmployeeId(@PathVariable("employeeId") Long employeeId,
                                               @RequestHeader(SecurityConstants.FROM_SOURCE) String source);

    /**
     * 按员工信息幂等开通账号
     *
     * @param user   员工信息（userName 为工号）
     * @param source 请求来源（inner）
     * @return 账号
     */
    @PostMapping("/provision")
    ApiResponse<SysUser> provision(@RequestBody SysUser user,
                                   @RequestHeader(SecurityConstants.FROM_SOURCE) String source);

    /**
     * 按员工ID停用账号
     *
     * @param employeeId ORG 员工ID
     * @param source     请求来源（inner）
     * @return 影响账号数
     */
    @PostMapping("/provision/disable/{employeeId}")
    ApiResponse<Integer> disableByEmployeeId(@PathVariable("employeeId") Long employeeId,
                                             @RequestHeader(SecurityConstants.FROM_SOURCE) String source);

}
