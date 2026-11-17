package net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamOauthClientPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * OIDC 客户端 Mapper（SEC-EIAM-DSN-CR-002）
 *
 * @author hwyz_leo
 */
@Mapper
public interface EiamOauthClientMapper extends BaseMapper<EiamOauthClientPo> {
}
