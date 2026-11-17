package net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.eiam.service.infrastructure.persistence.po.EiamSyncWatermarkPo;
import org.apache.ibatis.annotations.Mapper;

/**
 * 同步水位 Mapper（SEC-EIAM-DSN-CR-002）
 *
 * @author hwyz_leo
 */
@Mapper
public interface EiamSyncWatermarkMapper extends BaseMapper<EiamSyncWatermarkPo> {
}
