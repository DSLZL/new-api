/*
Copyright (C) 2025 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/

import React, { useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Card,
  Space,
  Tag,
  Typography,
  Input,
  Button,
  Spin,
  Empty,
  Descriptions,
  Table,
} from '@douyinfe/semi-ui';
import { IconSearch } from '@douyinfe/semi-icons';
import { API, showError } from '../../helpers';
import UserAssociations from './UserAssociations';

const { Title, Text } = Typography;

const summaryCards = [
  {
    title: 'Tier 判定',
    value: 'Tier 1 / 2 / 3 / 4',
    desc: '直接展示分层结论与 explanation，便于快速定性证据强度。',
    color: 'red',
  },
  {
    title: '命中维度',
    value: 'matched_dimensions',
    desc: '按 device / network / behavior / environment 汇总命中信号。',
    color: 'green',
  },
  {
    title: '时序对比',
    value: '48 bins 热力条',
    desc: '支持目标用户与关联用户活跃分布并排比对，辅助识别切换行为。',
    color: 'cyan',
  },
  {
    title: '代理风险提示',
    value: 'VPN / 机房IP',
    desc: '结合 datacenter_rate、共享IP、网络维度命中做前端风险提醒。',
    color: 'orange',
  },
];

const dimensionCatalog = [
  {
    category: 'device',
    title: '设备维度（device）',
    color: 'blue',
    dimensions: [
      {
        name: 'persistent_id',
        desc: '跨会话设备稳定标识。命中通常意味着硬件/浏览器指纹连续性较强。',
      },
      {
        name: 'etag_id',
        desc: '缓存标识轨迹。命中可反映同一设备链路中的长期缓存复用。',
      },
      {
        name: 'ua_similarity',
        desc: '浏览器/系统组合相似度。用于衡量客户端软件栈一致程度。',
      },
    ],
  },
  {
    category: 'network',
    title: '网络维度（network）',
    color: 'cyan',
    dimensions: [
      {
        name: 'webrtc_ip',
        desc: 'WebRTC 暴露地址相似性。可辅助识别代理后真实网络轨迹。',
      },
      {
        name: 'dns_resolver_ip',
        desc: 'DNS 解析器地址重合情况。可反映网络出口与环境共性。',
      },
      {
        name: 'asn_similarity',
        desc: '自治系统号相似度。用于识别网络运营商/机房路径接近性。',
      },
    ],
  },
  {
    category: 'behavior',
    title: '行为维度（behavior）',
    color: 'green',
    dimensions: [
      {
        name: 'time_similarity',
        desc: '活跃时段分布相似度。用于衡量两账号日内行为节律重叠。',
      },
      {
        name: 'mutual_exclusion',
        desc: '互斥切换强度。强调同一时段“此消彼长”的账号切换迹象。',
      },
      {
        name: 'keystroke_similarity',
        desc: '键盘行为模式相似度。用于识别输入节奏与停顿特征一致性。',
      },
      {
        name: 'mouse_similarity',
        desc: '鼠标行为模式相似度。用于识别轨迹、速度、停顿等动作特征。',
      },
    ],
  },
  {
    category: 'environment',
    title: '环境维度（environment）',
    color: 'orange',
    dimensions: [
      {
        name: 'ua_similarity',
        desc: '环境角度下的 UA 相似指标，可与设备维度结果交叉验证。',
      },
      {
        name: 'dns_resolver_ip',
        desc: '解析环境稳定性信号之一，常与网络/行为维度联合解释。',
      },
      {
        name: 'etag_id',
        desc: '环境缓存痕迹维度补充，适合用于“弱信号叠加”场景解释。',
      },
    ],
  },
];

const matchGuideItems = [
  {
    title: 'matched_dimensions',
    desc: '当前关联候选中被判定“命中”的维度列表，反映命中面。',
  },
  {
    title: 'weight',
    desc: '单维度在总体评分中的权重，权重越高，对最终结果影响越大。',
  },
  {
    title: 'score',
    desc: '单维度相似度/命中强度，通常在 0~1。可与 weight 联合判断贡献度。',
  },
  {
    title: 'Tier',
    desc: '基于综合证据的分层结论（Tier 1~4），用于快速风险分级与复核优先级排序。',
  },
];

const safeInt = (value) => {
  if (value === null || value === undefined || value === '') return null;
  const n = parseInt(String(value), 10);
  return Number.isFinite(n) && n > 0 ? n : null;
};

const displayValue = (value) => {
  if (value === null || value === undefined || value === '') return '-';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return String(value);
  if (Array.isArray(value)) return value.length ? value.join(', ') : '-';
  return String(value);
};

const parseJSONArray = (value) => {
  if (!value) return [];
  if (Array.isArray(value)) return value.filter(Boolean);
  try {
    const parsed = JSON.parse(String(value).trim());
    return Array.isArray(parsed) ? parsed.filter(Boolean) : [];
  } catch {
    return [];
  }
};

const formatBehaviorMetric = (value, fractionDigits = 1) => {
  if (value === null || value === undefined || value === '') return '-';
  const n = Number(value);
  if (!Number.isFinite(n)) return displayValue(value);
  return n.toFixed(fractionDigits);
};

const getWebRTCConsistency = (fingerprint) => {
  const requestIP = String(fingerprint?.ip_address || '').trim();
  const publicIPs = parseJSONArray(fingerprint?.webrtc_public_ips);
  if (!requestIP || publicIPs.length === 0) return '-';
  return publicIPs.includes(requestIP) ? '一致' : '不一致';
};

const getDetailFieldValue = (fingerprint, key) => {
  switch (key) {
    case 'webrtc_public_ips':
    case 'webrtc_local_ips':
      return displayValue(parseJSONArray(fingerprint?.[key]));
    case 'webrtc_request_ip_consistency':
      return getWebRTCConsistency(fingerprint);
    case 'typing_speed':
      return formatBehaviorMetric(fingerprint?.behavior_profile?.typing_speed);
    case 'typing_samples':
      return displayValue(fingerprint?.behavior_profile?.typing_samples);
    case 'mouse_avg_speed':
      return formatBehaviorMetric(
        fingerprint?.behavior_profile?.mouse_avg_speed,
      );
    case 'mouse_samples':
      return displayValue(fingerprint?.behavior_profile?.mouse_samples);
    default:
      return displayValue(fingerprint?.[key]);
  }
};

const getBehaviorSampleCount = (fingerprint, key) => {
  const profile = fingerprint?.behavior_profile;
  if (!profile || typeof profile !== 'object') return 0;
  if (key === 'typing_speed') return Number(profile.typing_samples) || 0;
  if (key === 'mouse_avg_speed') return Number(profile.mouse_samples) || 0;
  return 0;
};

const getCollectedState = (fingerprint, item, value) => {
  if (
    item.dimension === 'typing_speed' ||
    item.dimension === 'mouse_avg_speed'
  ) {
    return getBehaviorSampleCount(fingerprint, item.dimension) > 0;
  }
  return value !== '-';
};

const matchDetailCatalog = [
  {
    dimension: 'ja4',
    display_name: 'JA4',
    category: 'device',
    valueKey: 'ja4',
  },
  {
    dimension: 'webrtc_public_ips',
    display_name: 'WebRTC 公网 IP',
    category: 'network',
    valueKey: 'webrtc_public_ips',
  },
  {
    dimension: 'webrtc_local_ips',
    display_name: 'WebRTC 内网 IP',
    category: 'network',
    valueKey: 'webrtc_local_ips',
  },
  {
    dimension: 'http_header_hash',
    display_name: 'HTTP Header 指纹',
    category: 'environment',
    valueKey: 'http_header_hash',
  },
  {
    dimension: 'webgl_renderer',
    display_name: 'WebGL 渲染器',
    category: 'device',
    valueKey: 'webgl_renderer',
  },
  {
    dimension: 'webgl_vendor',
    display_name: 'WebGL 供应商',
    category: 'device',
    valueKey: 'webgl_vendor',
  },
  {
    dimension: 'media_device_total',
    display_name: '设备数量',
    category: 'device',
    valueKey: 'media_device_total',
  },
  {
    dimension: 'speech_voice_count',
    display_name: '语音引擎数量',
    category: 'environment',
    valueKey: 'speech_voice_count',
  },
  {
    dimension: 'typing_speed',
    display_name: '打字速度',
    category: 'behavior',
    valueKey: 'typing_speed',
  },
  {
    dimension: 'mouse_avg_speed',
    display_name: '鼠标速度',
    category: 'behavior',
    valueKey: 'mouse_avg_speed',
  },
];

const detailFields = [
  { key: 'ip_address', label: 'ip_address' },
  { key: 'persistent_id', label: 'persistent_id' },
  { key: 'etag_id', label: 'etag_id' },
  { key: 'dns_resolver_ip', label: 'dns_resolver_ip' },
  { key: 'ja4', label: 'ja4' },
  { key: 'http_header_hash', label: 'http_header_hash' },
  { key: 'webrtc_public_ips', label: 'webrtc_public_ips' },
  { key: 'webrtc_local_ips', label: 'webrtc_local_ips' },
  {
    key: 'webrtc_request_ip_consistency',
    label: 'webrtc_request_ip_consistency',
  },
  { key: 'webgl_renderer', label: 'webgl_renderer' },
  { key: 'webgl_vendor', label: 'webgl_vendor' },
  { key: 'webgl_deep_hash', label: 'webgl_deep_hash' },
  { key: 'canvas_hash', label: 'canvas_hash' },
  { key: 'webgl_hash', label: 'webgl_hash' },
  { key: 'client_rects_hash', label: 'client_rects_hash' },
  { key: 'media_devices_hash', label: 'media_devices_hash' },
  { key: 'media_device_count', label: 'media_device_count' },
  { key: 'media_device_group_hash', label: 'media_device_group_hash' },
  { key: 'media_device_total', label: 'media_device_total' },
  { key: 'speech_voices_hash', label: 'speech_voices_hash' },
  { key: 'speech_voice_count', label: 'speech_voice_count' },
  { key: 'speech_local_voice_count', label: 'speech_local_voice_count' },
  { key: 'typing_speed', label: 'typing_speed' },
  { key: 'typing_samples', label: 'typing_samples' },
  { key: 'mouse_avg_speed', label: 'mouse_avg_speed' },
  { key: 'mouse_samples', label: 'mouse_samples' },
];

const Fingerprint = () => {
  const { t } = useTranslation();
  const [detailUserId, setDetailUserId] = useState('');
  const [detailLoading, setDetailLoading] = useState(false);
  const [latestFingerprint, setLatestFingerprint] = useState(null);
  const [latestBehaviorProfile, setLatestBehaviorProfile] = useState(null);
  const [detailQueried, setDetailQueried] = useState(false);
  const detailRequestSeqRef = useRef(0);
  const detailActiveUserIdRef = useRef(null);

  const detailFingerprint = useMemo(
    () =>
      latestFingerprint
        ? {
            ...latestFingerprint,
            behavior_profile: latestBehaviorProfile,
          }
        : latestBehaviorProfile
          ? { behavior_profile: latestBehaviorProfile }
          : null,
    [latestBehaviorProfile, latestFingerprint],
  );

  const detailRows = useMemo(
    () =>
      detailFields.map((item) => ({
        key: item.label,
        value: getDetailFieldValue(detailFingerprint, item.key),
      })),
    [detailFingerprint],
  );

  const matchDetailRows = useMemo(
    () =>
      matchDetailCatalog.map((item, idx) => {
        const value = getDetailFieldValue(detailFingerprint, item.valueKey);
        return {
          id: `${item.dimension}-${idx}`,
          dimension: item.display_name,
          category: item.category,
          value,
          collected: getCollectedState(detailFingerprint, item, value),
        };
      }),
    [detailFingerprint],
  );

  const fetchLatestFingerprint = async () => {
    const safeUserId = safeInt(detailUserId);
    if (!safeUserId) {
      showError(t('请输入有效的用户ID（纯数字）'));
      return;
    }

    const requestId = detailRequestSeqRef.current + 1;
    detailRequestSeqRef.current = requestId;
    detailActiveUserIdRef.current = safeUserId;
    setDetailLoading(true);
    try {
      const res = await API.get(
        `/api/admin/fingerprint/user/${safeUserId}/fingerprints?limit=1`,
      );
      if (
        requestId !== detailRequestSeqRef.current ||
        detailActiveUserIdRef.current !== safeUserId
      ) {
        return;
      }
      if (res.data.success) {
        const rows = Array.isArray(res.data.data) ? res.data.data : [];
        const latestRow = rows[0] || null;
        setLatestFingerprint(latestRow ? { ...latestRow } : null);
        setLatestBehaviorProfile(
          res.data.behavior_profile &&
            typeof res.data.behavior_profile === 'object'
            ? { ...res.data.behavior_profile }
            : null,
        );
        setDetailQueried(true);
      } else {
        setLatestFingerprint(null);
        setLatestBehaviorProfile(null);
        setDetailQueried(true);
        showError(res.data.message || t('查询失败'));
      }
    } catch (e) {
      if (
        requestId !== detailRequestSeqRef.current ||
        detailActiveUserIdRef.current !== safeUserId
      ) {
        return;
      }
      setLatestFingerprint(null);
      setLatestBehaviorProfile(null);
      setDetailQueried(true);
      showError(e.message || t('网络错误'));
    }
    if (
      requestId === detailRequestSeqRef.current &&
      detailActiveUserIdRef.current === safeUserId
    ) {
      setDetailLoading(false);
    }
  };

  return (
    <div className='mt-[60px] px-2'>
      <div className='space-y-3'>
        <Card
          className='!rounded-2xl shadow-sm border-0'
          bodyStyle={{ padding: '14px 16px' }}
        >
          <div className='flex flex-wrap items-start justify-between gap-2'>
            <div>
              <Title heading={5} className='!mb-1'>
                {t('指纹关联分析管理')}
              </Title>
              <Text type='secondary' size='small'>
                {t(
                  '用于管理员复核多账号关联结果，支持按设备基准比对、Tier 分层解释、时序画像对比和 VPN/代理风险提示。',
                )}
              </Text>
            </div>
            <Space wrap>
              <Tag color='blue' size='small'>
                {t('Phase Final')}
              </Tag>
              <Tag color='cyan' size='small'>
                {t('Tier / Explanation / Matched Dimensions')}
              </Tag>
              <Tag color='orange' size='small'>
                {t('Temporal Compare / VPN Risk')}
              </Tag>
            </Space>
          </div>

          <div className='mt-3 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2'>
            {summaryCards.map((item) => (
              <div
                key={item.title}
                className='rounded-xl border border-gray-100 bg-gray-50 p-3'
              >
                <div className='flex items-center justify-between mb-1'>
                  <Text size='small' type='secondary'>
                    {t(item.title)}
                  </Text>
                  <Tag size='small' color={item.color}>
                    {t('已启用')}
                  </Tag>
                </div>
                <Text strong className='block text-sm'>
                  {t(item.value)}
                </Text>
                <Text size='small' type='tertiary'>
                  {t(item.desc)}
                </Text>
              </div>
            ))}
          </div>
        </Card>

        <Card
          className='!rounded-2xl shadow-sm border-0'
          bodyStyle={{ padding: '14px 16px' }}
        >
          <div className='flex flex-wrap items-center justify-between gap-2'>
            <Title heading={6} className='!mb-0'>
              {t('维度目录 / 命中详情说明')}
            </Title>
            <Tag color='purple' size='small'>
              {t('指纹详情页重点维度')}
            </Tag>
          </div>

          <div className='mt-3 rounded-xl border border-blue-100 bg-blue-50 p-3'>
            <div className='flex flex-wrap items-center justify-between gap-2'>
              <Text strong>{t('最新指纹维度详情')}</Text>
              <Tag size='small' color='blue'>
                {t('GET /api/admin/fingerprint/user/:id/fingerprints?limit=1')}
              </Tag>
            </div>

            <div className='mt-2 flex flex-wrap items-center gap-2'>
              <Input
                value={detailUserId}
                onChange={(val) => {
                  const nextUserId = val.replace(/[^0-9]/g, '');
                  detailRequestSeqRef.current += 1;
                  detailActiveUserIdRef.current = safeInt(nextUserId);
                  setDetailLoading(false);
                  setLatestFingerprint(null);
                  setLatestBehaviorProfile(null);
                  setDetailQueried(false);
                  setDetailUserId(nextUserId);
                }}
                placeholder={t('输入用户ID查看最新指纹')}
                style={{ width: 220 }}
              />
              <Button
                theme='solid'
                type='primary'
                icon={<IconSearch />}
                loading={detailLoading}
                onClick={fetchLatestFingerprint}
              >
                {t('拉取最新指纹')}
              </Button>
            </div>

            <div className='mt-3'>
              {detailLoading ? (
                <Spin />
              ) : !detailQueried ? (
                <Empty
                  image={null}
                  title={t('请输入用户ID并查询')}
                  description={t('将展示真实指纹字段值，而非仅说明文本')}
                />
              ) : !detailFingerprint ? (
                <Empty
                  image={null}
                  title={t('暂无指纹数据')}
                  description={t('该用户当前没有可展示的指纹记录')}
                />
              ) : (
                <div className='space-y-3'>
                  <div className='grid grid-cols-1 md:grid-cols-2 gap-3'>
                    <div className='rounded-xl border border-emerald-100 bg-emerald-50 p-3'>
                      <div className='flex items-center justify-between gap-2 mb-2'>
                        <Text strong>{t('WebRTC 泄露摘要')}</Text>
                        <Tag size='small' color='green'>
                          {t('显式展示')}
                        </Tag>
                      </div>
                      <Space vertical spacing={6} align='start'>
                        <Text size='small'>
                          <Text strong>{t('公网 IP')}：</Text>
                          {getDetailFieldValue(
                            detailFingerprint,
                            'webrtc_public_ips',
                          )}
                        </Text>
                        <Text size='small'>
                          <Text strong>{t('内网 IP')}：</Text>
                          {getDetailFieldValue(
                            detailFingerprint,
                            'webrtc_local_ips',
                          )}
                        </Text>
                        <Text size='small'>
                          <Text strong>{t('与请求 IP 一致性')}：</Text>
                          {getDetailFieldValue(
                            detailFingerprint,
                            'webrtc_request_ip_consistency',
                          )}
                        </Text>
                      </Space>
                    </div>

                    <div className='rounded-xl border border-violet-100 bg-violet-50 p-3'>
                      <div className='flex items-center justify-between gap-2 mb-2'>
                        <Text strong>{t('行为画像摘要')}</Text>
                        <Tag size='small' color='violet'>
                          {t('显式展示')}
                        </Tag>
                      </div>
                      <Space vertical spacing={6} align='start'>
                        <Text size='small'>
                          <Text strong>{t('打字速度')}：</Text>
                          {getDetailFieldValue(
                            detailFingerprint,
                            'typing_speed',
                          )}
                        </Text>
                        <Text size='small'>
                          <Text strong>{t('打字样本')}：</Text>
                          {getDetailFieldValue(
                            detailFingerprint,
                            'typing_samples',
                          )}
                        </Text>
                        <Text size='small'>
                          <Text strong>{t('鼠标速度')}：</Text>
                          {getDetailFieldValue(
                            detailFingerprint,
                            'mouse_avg_speed',
                          )}
                        </Text>
                        <Text size='small'>
                          <Text strong>{t('鼠标样本')}：</Text>
                          {getDetailFieldValue(
                            detailFingerprint,
                            'mouse_samples',
                          )}
                        </Text>
                      </Space>
                    </div>
                  </div>

                  <Descriptions data={detailRows} column={2} />
                  <div className='rounded-xl border border-cyan-100 bg-cyan-50 p-3'>
                    <div className='flex flex-wrap items-center justify-between gap-2'>
                      <Text strong>{t('指纹重点维度采集情况')}</Text>
                      <Tag size='small' color='cyan'>
                        {matchDetailRows.length} {t('项')}
                      </Tag>
                    </div>
                    <Text size='small' type='secondary' className='block mt-1'>
                      {t(
                        '此处仅展示当前最新指纹是否采集到关键字段，不代表与其他账号的真实匹配/不匹配结论。真实命中维度请在关联分析结果中结合 matched_dimensions 与 details 解读。',
                      )}
                    </Text>
                    {!matchDetailRows.length ? (
                      <Empty
                        image={null}
                        title={t('暂无维度数据')}
                        description={t('关键字段采集情况会在此展示')}
                      />
                    ) : (
                      <Table
                        size='small'
                        pagination={false}
                        rowKey='id'
                        dataSource={matchDetailRows}
                        columns={[
                          {
                            title: t('维度'),
                            dataIndex: 'dimension',
                            render: (value) => <Text strong>{value}</Text>,
                          },
                          {
                            title: t('分类'),
                            dataIndex: 'category',
                            render: (value) => (
                              <Tag size='small'>{value || '-'}</Tag>
                            ),
                          },
                          {
                            title: t('当前值'),
                            dataIndex: 'value',
                            render: (value) => (
                              <Text
                                ellipsis={{ showTooltip: true }}
                                style={{ maxWidth: 220, fontSize: 12 }}
                              >
                                {value}
                              </Text>
                            ),
                          },
                          {
                            title: t('采集状态'),
                            dataIndex: 'collected',
                            render: (value) => (
                              <Tag
                                color={value ? 'green' : 'grey'}
                                size='small'
                              >
                                {value ? t('已采集') : t('缺失/不可判断')}
                              </Tag>
                            ),
                          },
                        ]}
                      />
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className='mt-3 grid grid-cols-1 md:grid-cols-2 gap-3'>
            {dimensionCatalog.map((group) => (
              <div
                key={group.category}
                className='rounded-xl border border-gray-100 bg-gray-50 p-3'
              >
                <div className='flex items-center justify-between mb-2'>
                  <Text strong>{t(group.title)}</Text>
                  <Tag color={group.color} size='small'>
                    {group.dimensions.length} {t('项')}
                  </Tag>
                </div>
                <Space vertical spacing={6} align='start'>
                  {group.dimensions.map((dim) => (
                    <div key={`${group.category}-${dim.name}`}>
                      <Tag color='grey' size='small'>
                        {dim.name}
                      </Tag>
                      <Text size='small' type='tertiary' className='!ml-1'>
                        {t(dim.desc)}
                      </Text>
                    </div>
                  ))}
                </Space>
              </div>
            ))}
          </div>

          <div className='mt-3 rounded-xl border border-cyan-100 bg-cyan-50 p-3'>
            <Text strong>{t('命中详情怎么看')}</Text>
            <div className='mt-2 grid grid-cols-1 md:grid-cols-2 gap-2'>
              {matchGuideItems.map((item) => (
                <div
                  key={item.title}
                  className='rounded-lg border border-white/80 bg-white/80 p-2'
                >
                  <Tag color='cyan' size='small'>
                    {item.title}
                  </Tag>
                  <Text size='small' type='secondary' className='block mt-1'>
                    {t(item.desc)}
                  </Text>
                </div>
              ))}
            </div>
          </div>
        </Card>

        <UserAssociations />
      </div>
    </div>
  );
};

export default Fingerprint;
