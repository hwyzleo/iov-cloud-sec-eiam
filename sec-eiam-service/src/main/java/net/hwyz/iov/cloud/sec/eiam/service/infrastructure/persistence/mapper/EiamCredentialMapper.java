package net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamCredentialPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * EIAM 员工登录凭据 Mapper（SEC-EIAM-DSN-CR-002 原地修订·第二次）
 *
 * @author hwyz_leo
 */
@Mapper
public interface EiamCredentialMapper extends BaseMapper<EiamCredentialPo> {
}
