package net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamIdentityPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * 员工身份目录 Mapper（SEC-EIAM-DSN-CR-002）
 *
 * @author hwyz_leo
 */
@Mapper
public interface EiamIdentityMapper extends BaseMapper<EiamIdentityPo> {
}
