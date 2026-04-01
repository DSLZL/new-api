import React, { useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Card,
  Button,
  Tag,
  Table,
  Typography,
  Space,
  Select,
  Input,
  Spin,
  Empty,
  Collapse,
  Banner,
  Progress,
  Avatar,
  Descriptions,
} from '@douyinfe/semi-ui';
import {
  IconSearch,
  IconRefresh,
  IconLink,
  IconUser,
  IconTick,
  IconClose,
  IconAlertTriangle,
} from '@douyinfe/semi-icons';
import { API, showError } from '../../helpers';

const { Text, Title } = Typography;

const UserAssociations = ({ userId: initialUserId }) => {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [minConfidence, setMinConfidence] = useState(0.3);
  const [queried, setQueried] = useState(false);
  const [inputUserId, setInputUserId] = useState(initialUserId || '');
  const [deviceProfiles, setDeviceProfiles] = useState({});  // { userId: profiles[] }
  const [deviceLoading, setDeviceLoading] = useState({});   // { userId: bool }
  const [expandedDevices, setExpandedDevices] = useState({}); // { userId: bool }
  const [selectedFpId, setSelectedFpId] = useState(null);
  const [selectedFpInfo, setSelectedFpInfo] = useState(null);


  const getConfidenceColor = (conf) => {
    if (conf >= 0.85) return 'red';
    if (conf >= 0.7) return 'orange';
    if (conf >= 0.5) return 'yellow';
    return 'green';
  };

  const getRiskTag = (level) => {
    const map = {
      critical: { color: 'red', text: t('极高风险') },
      high: { color: 'orange', text: t('高风险') },
      medium: { color: 'yellow', text: t('中等风险') },
      low: { color: 'green', text: t('低风险') },
    };
    return map[level] || map.low;
  };

  const getCategoryIcon = (cat) => {
    const map = {
      device: '🖥️',
      network: '🌐',
      environment: '⚙️',
    };
    return map[cat] || '📊';
  };

  const queryAssociations = useCallback(
    async (refresh = false, fpId = selectedFpId) => {
      if (!inputUserId) {
        showError(t('请输入用户ID'));
        return;
      }
      setLoading(true);
      try {
        let url = `/api/admin/fingerprint/user/${inputUserId}/associations?min_confidence=${minConfidence}&limit=20&refresh=${refresh}`;
        if (fpId) {
          url += `&fingerprint_id=${fpId}`;
        }
        const res = await API.get(url);
        if (res.data.success) {
          setResult(res.data.data);
          setQueried(true);
        } else {
          showError(res.data.message || t('查询失败'));
        }
      } catch (e) {
        showError(e.message || t('网络错误'));
      }
      setLoading(false);
    },
    [inputUserId, minConfidence, t, selectedFpId],
  );

  const fetchDeviceProfiles = useCallback(async (userId) => {
    setExpandedDevices((prev) => {
      const next = { ...prev, [userId]: !prev[userId] };
      // 仅在展开且尚未加载时请求
      if (next[userId] && deviceProfiles[userId] === undefined && !deviceLoading[userId]) {
        setDeviceLoading((dl) => ({ ...dl, [userId]: true }));
        API.get(`/api/admin/fingerprint/user/${userId}/devices`)
          .then((res) => {
            if (res.data.success) {
              setDeviceProfiles((dp) => ({ ...dp, [userId]: res.data.data || [] }));
            }
          })
          .catch(() => {
            setDeviceProfiles((dp) => ({ ...dp, [userId]: [] }));
          })
          .finally(() => {
            setDeviceLoading((dl) => ({ ...dl, [userId]: false }));
          });
      }
      return next;
    });
  }, [deviceProfiles, deviceLoading]);

  const handleAction = async (targetUserId, action) => {
    // 先找到或创建关联记录，然后审核
    try {
      // 尝试找到已有的link
      const assoc = result?.associations?.find(
        (a) => a.user.id === targetUserId,
      );
      if (assoc?.existing_link) {
        await API.post(
          `/api/admin/fingerprint/links/${assoc.existing_link.link_id}/review`,
          { action, note: '' },
        );
      }
      // 重新查询
      queryAssociations(true);
    } catch (e) {
      showError(e.message);
    }
  };


  return (
    <Card
      className='!rounded-2xl shadow-sm border-0'
      bodyStyle={{ padding: '16px' }}
    >
      {/* 头部 */}
      <div className='flex items-center mb-3'>
        <Avatar size='small' color='cyan' className='mr-2 shadow-md'>
          <IconLink size={16} />
        </Avatar>
        <div>
          <Text className='text-lg font-medium'>{t('关联账号查询')}</Text>
          <div className='text-xs text-gray-500'>
            {t('基于设备指纹、网络特征等多维度分析，查找可能的关联账号')}
          </div>
        </div>
      </div>

      {/* 操作栏 */}
      <div className='flex flex-col gap-3 mb-4'>
        <div className='flex items-center gap-2'>
          <Input
            value={inputUserId}
            onChange={setInputUserId}
            placeholder={t('请输入用户ID')}
            style={{ width: 200 }}
            prefix={<IconUser />}
          />
        </div>
        <div className='flex items-center gap-3 flex-wrap'>
        <Select
          value={minConfidence}
          onChange={setMinConfidence}
          style={{ width: 200 }}
          optionList={[
            { label: `0.2 (${t('宽松')})`, value: 0.2 },
            { label: `0.3 (${t('默认')})`, value: 0.3 },
            { label: `0.5 (${t('较严格')})`, value: 0.5 },
            { label: `0.7 (${t('严格')})`, value: 0.7 },
          ]}
          prefix={t('最低置信度')}
        />

        <Button
          theme='solid'
          type='primary'
          icon={<IconSearch />}
          loading={loading}
          onClick={() => queryAssociations(false)}
        >
          {t('查询关联账号')}
        </Button>


        {queried && (
          <Button
            theme='light'
            icon={<IconRefresh />}
            loading={loading}
            onClick={() => queryAssociations(true)}
          >
            {t('强制刷新')}
          </Button>
        )}
        </div>
      </div>

      {/* 结果 */}
      <Spin spinning={loading}>
        {result && (
          <>
            {/* 概要 */}
            <Banner
              type='info'
              description={
                <Space>
                  <Text>
                    {t('分析耗时')}: {result.time_cost_ms}ms
                  </Text>
                  <Text>
                    {t('候选账号')}: {result.candidates_found}
                  </Text>
                  <Text>
                    {t('匹配结果')}: {result.associations?.length || 0}
                  </Text>
                </Space>
              }
              className='mb-4'
            />

            {selectedFpId && (
              <Banner
                fullMode={false}
                type='info'
                bordered
                className='mb-3'
                title={t('当前比对基准设备')}
                description={
                  <div className='flex items-center justify-between w-full'>
                    <span>
                      {selectedFpInfo?.ua_browser || '-'} / {selectedFpInfo?.ua_os || '-'} ({selectedFpInfo?.device_key?.slice(0, 8) || 'N/A'})
                    </span>
                    <Button
                      size='small'
                      type='warning'
                      theme='light'
                      onClick={() => {
                        setSelectedFpId(null);
                        setSelectedFpInfo(null);
                        queryAssociations(false, null);
                      }}
                    >
                      {t('重置为默认')}
                    </Button>
                  </div>
                }
              />
            )}

            {(!result.associations || result.associations.length === 0) ? (
              <Empty
                title={t('未发现关联账号')}
                description={t('该用户暂未发现与其他账号的关联')}
              />
            ) : (
              <div className='space-y-3'>
                {result.associations.map((assoc, idx) => {
                  const riskTag = getRiskTag(assoc.risk_level);
                  return (
                    <Card
                      key={idx}
                      className='!rounded-xl'
                      bodyStyle={{ padding: '12px 16px' }}
                    >
                      {/* 用户信息 + 置信度 */}
                      <div className='flex items-center justify-between flex-wrap gap-2 mb-2'>
                        <div className='flex items-center gap-2'>
                          <Avatar size='small' color='blue'>
                            <IconUser size={14} />
                          </Avatar>
                          <div>
                            <Text strong>
                              #{assoc.user.id} {assoc.user.username}
                            </Text>
                            <div className='text-xs text-gray-500'>
                              {assoc.user.email || '-'} | {t('注册')}:{' '}
                              {new Date(
                                assoc.user.created_at,
                              ).toLocaleDateString()}
                            </div>
                          </div>
                        </div>

                        <div className='flex items-center gap-2'>
                          <Progress
                            percent={Math.round(assoc.confidence * 100)}
                            size='small'
                            stroke={
                              getConfidenceColor(assoc.confidence) ===
                              'red'
                                ? '#f5222d'
                                : getConfidenceColor(assoc.confidence) ===
                                    'orange'
                                  ? '#fa8c16'
                                  : getConfidenceColor(
                                        assoc.confidence,
                                      ) === 'yellow'
                                    ? '#faad14'
                                    : '#52c41a'
                            }
                            style={{ width: 80 }}
                            showInfo
                            format={(p) => `${p}%`}
                          />
                          <Tag color={riskTag.color} size='small'>
                            {riskTag.text}
                          </Tag>
                          <Tag size='small'>
                            {assoc.match_dimensions}/{assoc.total_dimensions}{' '}
                            {t('维度匹配')}
                          </Tag>
                        </div>
                      </div>

                      {/* 共享IP */}
                      {assoc.shared_ips && assoc.shared_ips.length > 0 && (
                        <div className='mb-2'>
                          <Text size='small' type='tertiary'>
                            {t('共享IP')}:{' '}
                          </Text>
                          {assoc.shared_ips.slice(0, 5).map((ip, i) => (
                            <Tag key={i} size='small' color='grey'>
                              {ip}
                            </Tag>
                          ))}
                          {assoc.shared_ips.length > 5 && (
                            <Text size='small' type='tertiary'>
                              ...+{assoc.shared_ips.length - 5}
                            </Text>
                          )}
                        </div>
                      )}

                      {/* 已有关联记录 */}
                      {assoc.existing_link && (
                        <div className='mb-2'>
                          <Tag size='small' color='violet'>
                            {t('已有关联记录')}: {assoc.existing_link.status}
                          </Tag>
                        </div>
                      )}

                      {/* 已知设备档案 (可折叠) */}
                      <div className='mt-2'>
                        <Button
                          size='small'
                          theme='borderless'
                          type='tertiary'
                          icon={expandedDevices[assoc.user.id] ? <IconClose size='small' /> : <IconSearch size='small' />}
                          onClick={() => fetchDeviceProfiles(assoc.user.id)}
                        >
                          {expandedDevices[assoc.user.id] ? t('收起设备档案') : t('已知设备')}
                        </Button>
                        {expandedDevices[assoc.user.id] && (
                          <div className='mt-2'>
                            {deviceLoading[assoc.user.id] ? (
                              <Spin size='small' />
                            ) : (deviceProfiles[assoc.user.id] || []).length === 0 ? (
                              <Text type='tertiary' size='small'>{t('暂无设备档案')}</Text>
                            ) : (
                              <Table
                                size='small'
                                pagination={false}
                                rowKey='id'
                                dataSource={deviceProfiles[assoc.user.id]}
                                columns={[
                                  {
                                    title: t('类型'),
                                    dataIndex: 'ua_device_type',
                                    width: 60,
                                    render: (v) => {
                                      const icon = v === 'mobile' ? '📱' : v === 'tablet' ? '📟' : '🖥️';
                                      return <span title={v}>{icon}</span>;
                                    },
                                  },
                                  {
                                    title: t('浏览器 / 系统'),
                                    dataIndex: 'ua_browser',
                                    render: (_, row) => (
                                      <Text size='small'>{row.ua_browser || '-'} / {row.ua_os || '-'}</Text>
                                    ),
                                  },
                                  {
                                    title: t('设备标识'),
                                    dataIndex: 'device_key',
                                    render: (v) => (
                                      <Text
                                        ellipsis={{ showTooltip: true }}
                                        style={{ maxWidth: 100, fontSize: 11, fontFamily: 'monospace' }}
                                      >
                                        {v ? v.slice(0, 12) + '…' : '-'}
                                      </Text>
                                    ),
                                  },
                                  {
                                    title: t('首次'),
                                    dataIndex: 'first_seen_at',
                                    width: 90,
                                    render: (v) => <Text size='small'>{v ? new Date(v).toLocaleDateString() : '-'}</Text>,
                                  },
                                  {
                                    title: t('最近'),
                                    dataIndex: 'last_seen_at',
                                    width: 90,
                                    render: (v) => <Text size='small'>{v ? new Date(v).toLocaleDateString() : '-'}</Text>,
                                  },
                                  {
                                    title: t('次数'),
                                    dataIndex: 'seen_count',
                                    width: 50,
                                    render: (v) => <Text size='small'>{v}</Text>,
                                  },
                                  {
                                    title: t('操作'),
                                    width: 80,
                                    render: (_, row) => (
                                      <Button
                                        size='small'
                                        theme='light'
                                        type={selectedFpId === row.id ? 'primary' : 'tertiary'}
                                        onClick={() => {
                                          setSelectedFpId(row.id);
                                          setSelectedFpInfo(row);
                                          queryAssociations(false, row.id);
                                        }}
                                      >
                                        {selectedFpId === row.id ? t('比对中') : t('比对')}
                                      </Button>
                                    ),
                                  },
                                ]}
                              />
                            )}
                          </div>
                        )}
                      </div>

                      {/* 匹配详情 (可折叠) */}
                      <Collapse>
                        <Collapse.Panel
                          header={t('查看匹配详情')}
                          itemKey='details'
                        >
                          <Table
                            columns={[
                              {
                                title: t('分类'),
                                dataIndex: 'category',
                                width: 80,
                                render: (cat) => (
                                  <span>
                                    {getCategoryIcon(cat)}{' '}
                                    {cat === 'device'
                                      ? t('设备')
                                      : cat === 'network'
                                        ? t('网络')
                                        : t('环境')}
                                  </span>
                                ),
                              },
                              {
                                title: t('维度'),
                                dataIndex: 'display_name',
                                width: 120,
                                render: (text) => <Text strong>{text}</Text>,
                              },
                              {
                                title: t('权重'),
                                dataIndex: 'weight',
                                width: 60,
                                render: (w) => <Text type='tertiary'>{w?.toFixed(2)}</Text>,
                              },
                              {
                                title: `${t('目标用户')} (#${inputUserId})`,
                                dataIndex: 'value_a',
                                width: 160,
                                render: (v) => (
                                  <Text
                                    ellipsis={{ showTooltip: true }}
                                    style={{ maxWidth: 150, fontSize: 12 }}
                                  >
                                    {v || '-'}
                                  </Text>
                                ),
                              },
                              {
                                title: `${t('关联用户')} (#${assoc.user.id})`,
                                dataIndex: 'value_b',
                                width: 160,
                                render: (v) => (
                                  <Text
                                    ellipsis={{ showTooltip: true }}
                                    style={{ maxWidth: 150, fontSize: 12 }}
                                  >
                                    {v || '-'}
                                  </Text>
                                ),
                              },
                              {
                                title: t('匹配'),
                                dataIndex: 'matched',
                                width: 80,
                                render: (matched, record) => {
                                  if (matched) {
                                    return (
                                      <Tag color='green' size='small'>
                                        <IconTick size='small' /> {t('匹配')}
                                      </Tag>
                                    );
                                  }
                                  if (record.score > 0) {
                                    return (
                                      <Tag color='yellow' size='small'>
                                        {(record.score * 100).toFixed(0)}%
                                      </Tag>
                                    );
                                  }
                                  return (
                                    <Tag color='red' size='small'>
                                      <IconClose size='small' /> {t('不匹配')}
                                    </Tag>
                                  );
                                },
                              },
                            ]}
                            dataSource={(assoc.details || []).sort(
                              (a, b) => (b.weight || 0) - (a.weight || 0),
                            )}
                            pagination={false}
                            size='small'
                            rowKey='dimension'
                          />
                        </Collapse.Panel>
                      </Collapse>

                      {/* 操作按钮 */}
                      <div className='flex gap-2 mt-2 flex-wrap'>
                        <Button
                          size='small'
                          onClick={() =>
                            window.open(
                              `/console/user?edit=${assoc.user.id}`,
                              '_blank',
                            )
                          }
                        >
                          {t('查看用户')}
                        </Button>
                        {assoc.existing_link && (
                          <>
                            <Button
                              size='small'
                              type='primary'
                              onClick={() =>
                                handleAction(assoc.user.id, 'confirm')
                              }
                            >
                              {t('确认关联')}
                            </Button>
                            <Button
                              size='small'
                              onClick={() =>
                                handleAction(assoc.user.id, 'whitelist')
                              }
                            >
                              {t('加入白名单')}
                            </Button>
                            <Button
                              size='small'
                              type='danger'
                              onClick={() =>
                                handleAction(assoc.user.id, 'ban_newer')
                              }
                            >
                              {t('封禁此账号')}
                            </Button>
                          </>
                        )}
                      </div>

                    </Card>
                  );
                })}
              </div>
            )}
          </>
        )}
      </Spin>
    </Card>
  );
};

export default UserAssociations;