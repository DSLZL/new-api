import React, { useState, useCallback, useEffect } from 'react';
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
} from '@douyinfe/semi-ui';
import {
  IconSearch,
  IconRefresh,
  IconLink,
  IconUser,
  IconTick,
  IconClose,
} from '@douyinfe/semi-icons';
import { API, showError } from '../../helpers';

const { Text } = Typography;

const safeInt = (value) => {
  if (value === null || value === undefined || value === '') return null;
  const n = parseInt(String(value), 10);
  return Number.isFinite(n) && n > 0 ? n : null;
};

const UserAssociations = ({ userId: initialUserId }) => {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [minConfidence, setMinConfidence] = useState(0.3);
  const [queried, setQueried] = useState(false);
  const [inputUserId, setInputUserId] = useState(initialUserId || '');
  const [deviceProfiles, setDeviceProfiles] = useState({});
  const [deviceLoading, setDeviceLoading] = useState({});
  const [expandedDevices, setExpandedDevices] = useState({});
  const [selectedProfileId, setSelectedProfileId] = useState(null);
  const [selectedProfileInfo, setSelectedProfileInfo] = useState(null);

  // ★ 新增: 目标用户自己的设备档案
  const [targetDevices, setTargetDevices] = useState([]);
  const [targetDevicesLoading, setTargetDevicesLoading] = useState(false);
  const [showTargetDevices, setShowTargetDevices] = useState(false);

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
    const map = { device: '🖥️', network: '🌐', environment: '⚙️' };
    return map[cat] || '📊';
  };

  const queryAssociations = useCallback(
    async (refresh = false, profileId = selectedProfileId) => {
      const safeUserId = safeInt(inputUserId);
      if (!safeUserId) {
        showError(t('请输入有效的用户ID（纯数字）'));
        return;
      }
      setLoading(true);
      try {
        let url = `/api/admin/fingerprint/user/${safeUserId}/associations?min_confidence=${minConfidence}&limit=20&refresh=${refresh}`;
        const safeProfileId = safeInt(profileId);
        if (safeProfileId) {
          url += `&device_profile_id=${safeProfileId}`;
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
    [inputUserId, minConfidence, t, selectedProfileId],
  );

  // ★ 新增: 获取目标用户自己的设备列表
  const fetchTargetDevices = useCallback(async () => {
    const safeUserId = safeInt(inputUserId);
    if (!safeUserId) return;

    setShowTargetDevices((prev) => !prev);

    // 已加载过就不重复请求
    if (targetDevices.length > 0) return;

    setTargetDevicesLoading(true);
    try {
      const res = await API.get(
        `/api/admin/fingerprint/user/${safeUserId}/devices`,
      );
      if (res.data.success) {
        setTargetDevices(res.data.data || []);
      }
    } catch {
      setTargetDevices([]);
    }
    setTargetDevicesLoading(false);
  }, [inputUserId, targetDevices.length]);

  // ★ 新增: 切换用户ID时清空旧的设备缓存
  useEffect(() => {
    setTargetDevices([]);
    setShowTargetDevices(false);
    setSelectedProfileId(null);
    setSelectedProfileInfo(null);
  }, [inputUserId]);

  const fetchDeviceProfiles = useCallback(
    async (userId) => {
      const safeUserId = safeInt(userId);
      if (!safeUserId) return;
      setExpandedDevices((prev) => {
        const next = { ...prev, [safeUserId]: !prev[safeUserId] };
        if (
          next[safeUserId] &&
          deviceProfiles[safeUserId] === undefined &&
          !deviceLoading[safeUserId]
        ) {
          setDeviceLoading((dl) => ({ ...dl, [safeUserId]: true }));
          API.get(`/api/admin/fingerprint/user/${safeUserId}/devices`)
            .then((res) => {
              if (res.data.success) {
                setDeviceProfiles((dp) => ({
                  ...dp,
                  [safeUserId]: res.data.data || [],
                }));
              }
            })
            .catch(() => {
              setDeviceProfiles((dp) => ({ ...dp, [safeUserId]: [] }));
            })
            .finally(() => {
              setDeviceLoading((dl) => ({ ...dl, [safeUserId]: false }));
            });
        }
        return next;
      });
    },
    [deviceProfiles, deviceLoading],
  );

  const handleAction = async (targetUserId, action) => {
    try {
      const assoc = result?.associations?.find(
        (a) => a.user.id === targetUserId,
      );
      if (assoc?.existing_link) {
        const safeLinkId = safeInt(assoc.existing_link.link_id);
        if (!safeLinkId) {
          showError(t('无效的关联记录ID'));
          return;
        }
        await API.post(
          `/api/admin/fingerprint/links/${safeLinkId}/review`,
          { action, note: '' },
        );
      }
      queryAssociations(true);
    } catch (e) {
      showError(e.message);
    }
  };

  const handleSelectProfile = useCallback(
    (row) => {
      const safeId = safeInt(row.id);
      if (!safeId) {
        showError(t('无效的设备档案ID'));
        return;
      }
      setSelectedProfileId(safeId);
      setSelectedProfileInfo(row);
      queryAssociations(false, safeId);
    },
    [queryAssociations, t],
  );

  // ★ 通用的设备表格列定义（目标用户 + 关联用户共用）
  const deviceColumns = [
    {
      title: t('类型'),
      dataIndex: 'ua_device_type',
      width: 60,
      render: (v) => {
        const icon =
          v === 'mobile' ? '📱' : v === 'tablet' ? '📟' : '🖥️';
        return <span title={v}>{icon}</span>;
      },
    },
    {
      title: t('浏览器 / 系统'),
      dataIndex: 'ua_browser',
      render: (_, row) => (
        <Text size='small'>
          {row.ua_browser || '-'} / {row.ua_os || '-'}
        </Text>
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
      render: (v) => (
        <Text size='small'>
          {v ? new Date(v).toLocaleDateString() : '-'}
        </Text>
      ),
    },
    {
      title: t('最近'),
      dataIndex: 'last_seen_at',
      width: 90,
      render: (v) => (
        <Text size='small'>
          {v ? new Date(v).toLocaleDateString() : '-'}
        </Text>
      ),
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
      render: (_, row) => {
        const rowProfileId = safeInt(row.id);
        return (
          <Button
            size='small'
            theme='light'
            type={
              selectedProfileId === rowProfileId ? 'primary' : 'tertiary'
            }
            disabled={!rowProfileId}
            onClick={() => handleSelectProfile(row)}
          >
            {selectedProfileId === rowProfileId ? t('比对中') : t('比对')}
          </Button>
        );
      },
    },
  ];

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
            onChange={(val) => setInputUserId(val.replace(/[^0-9]/g, ''))}
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

            {/* 当前比对基准设备 提示 */}
            {selectedProfileId && (
              <Banner
                fullMode={false}
                type='info'
                bordered
                className='mb-3'
                title={t('当前比对基准设备')}
                description={
                  <div className='flex items-center justify-between w-full'>
                    <span>
                      {selectedProfileInfo?.ua_browser || '-'} /{' '}
                      {selectedProfileInfo?.ua_os || '-'} (
                      {selectedProfileInfo?.device_key?.slice(0, 8) || 'N/A'}
                      )
                      {/* ★ 新增: 显示设备归属用户 */}
                      {selectedProfileInfo?.user_id && (
                        <Tag size='small' color='blue' className='ml-2'>
                          {t('所属用户')}: #{selectedProfileInfo.user_id}
                        </Tag>
                      )}
                    </span>
                    <Button
                      size='small'
                      type='warning'
                      theme='light'
                      onClick={() => {
                        setSelectedProfileId(null);
                        setSelectedProfileInfo(null);
                        queryAssociations(false, null);
                      }}
                    >
                      {t('重置为默认')}
                    </Button>
                  </div>
                }
              />
            )}

            {/* ═══════════════════════════════════════════════ */}
            {/* ★ 新增: 目标用户自己的设备档案（可折叠）        */}
            {/* ═══════════════════════════════════════════════ */}
            <Card
              className='!rounded-xl mb-3'
              bodyStyle={{ padding: '8px 12px' }}
              style={{ background: '#f0f7ff' }}
            >
              <div className='flex items-center justify-between'>
                <div className='flex items-center gap-2'>
                  <Avatar size='extra-small' color='blue'>
                    <IconUser size={12} />
                  </Avatar>
                  <Text strong>
                    {t('目标用户')} #{safeInt(inputUserId) || inputUserId}{' '}
                    {t('的设备档案')}
                  </Text>
                </div>
                <Button
                  size='small'
                  theme='borderless'
                  type='primary'
                  icon={
                    showTargetDevices ? (
                      <IconClose size='small' />
                    ) : (
                      <IconSearch size='small' />
                    )
                  }
                  onClick={fetchTargetDevices}
                >
                  {showTargetDevices
                    ? t('收起')
                    : t('展开设备列表')}
                </Button>
              </div>

              {showTargetDevices && (
                <div className='mt-2'>
                  {targetDevicesLoading ? (
                    <Spin size='small' />
                  ) : targetDevices.length === 0 ? (
                    <Text type='tertiary' size='small'>
                      {t('暂无设备档案')}
                    </Text>
                  ) : (
                    <Table
                      size='small'
                      pagination={false}
                      rowKey='id'
                      dataSource={targetDevices}
                      columns={deviceColumns}
                    />
                  )}
                </div>
              )}
            </Card>

            {/* 关联账号列表 */}
            {!result.associations || result.associations.length === 0 ? (
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
                              getConfidenceColor(assoc.confidence) === 'red'
                                ? '#f5222d'
                                : getConfidenceColor(assoc.confidence) ===
                                    'orange'
                                  ? '#fa8c16'
                                  : getConfidenceColor(assoc.confidence) ===
                                      'yellow'
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

                      {/* 关联用户的设备档案 (可折叠) */}
                      <div className='mt-2'>
                        <Button
                          size='small'
                          theme='borderless'
                          type='tertiary'
                          icon={
                            expandedDevices[assoc.user.id] ? (
                              <IconClose size='small' />
                            ) : (
                              <IconSearch size='small' />
                            )
                          }
                          onClick={() => fetchDeviceProfiles(assoc.user.id)}
                        >
                          {expandedDevices[assoc.user.id]
                            ? t('收起设备档案')
                            : t('已知设备')}
                        </Button>
                        {expandedDevices[assoc.user.id] && (
                          <div className='mt-2'>
                            {deviceLoading[assoc.user.id] ? (
                              <Spin size='small' />
                            ) : (deviceProfiles[assoc.user.id] || [])
                                .length === 0 ? (
                              <Text type='tertiary' size='small'>
                                {t('暂无设备档案')}
                              </Text>
                            ) : (
                              <Table
                                size='small'
                                pagination={false}
                                rowKey='id'
                                dataSource={deviceProfiles[assoc.user.id]}
                                columns={deviceColumns}
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
                                render: (w) => (
                                  <Text type='tertiary'>
                                    {w?.toFixed(2)}
                                  </Text>
                                ),
                              },
                              {
                                title: `${t('目标用户')} (#${safeInt(inputUserId) || inputUserId})`,
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