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

import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Modal,
  Typography,
  InputNumber,
  Button,
  Table,
  Badge,
  Space,
} from '@douyinfe/semi-ui';
import { timestamp2string } from '../../../helpers';

const { Text } = Typography;

const SECONDS_PER_DAY = 86400;

const statusTypeMap = {
  active: 'success',
  invalidated: 'warning',
  expired: 'danger',
  exhausted: 'danger',
};

const getExpireDays = (inviteCode) => {
  if (!inviteCode?.expires_at) return 1;
  const now = Math.floor(Date.now() / 1000);
  const diff = inviteCode.expires_at - now;
  return Math.max(1, Math.ceil(diff / SECONDS_PER_DAY));
};

const getExpireAtByDays = (days) => {
  const normalized = Number.isFinite(days) ? Math.max(1, Math.floor(days)) : 1;
  return Math.floor(Date.now() / 1000) + normalized * SECONDS_PER_DAY;
};

const renderStatus = (status, t) => {
  const map = {
    active: t('生效'),
    invalidated: t('已作废'),
    expired: t('已过期'),
    exhausted: t('已耗尽'),
  };
  return (
    <span className='flex items-center gap-2'>
      <Badge dot type={statusTypeMap[status] || 'primary'} />
      <span>{map[status] || status || '-'}</span>
    </span>
  );
};

const InviteCodeModal = ({
  visible,
  onCancel,
  t,
  inviteCode,
  inviteHistory,
  historyLoading,
  onRefreshHistory,
  onSaveRules,
  onRefreshCode,
  saving,
  refreshing,
}) => {
  const [maxUses, setMaxUses] = useState(1);
  const [expireDays, setExpireDays] = useState(1);
  const [refreshLength, setRefreshLength] = useState(8);
  const loadedForVisibleRef = useRef(false);

  useEffect(() => {
    if (!inviteCode) return;
    setMaxUses(Math.max(1, inviteCode.max_uses || 1));
    setExpireDays(getExpireDays(inviteCode));
    setRefreshLength(Math.max(4, Math.min(10, inviteCode.code?.length || 8)));
  }, [inviteCode]);

  useEffect(() => {
    if (!visible) {
      loadedForVisibleRef.current = false;
      return;
    }
    if (loadedForVisibleRef.current) return;
    loadedForVisibleRef.current = true;
    onRefreshHistory?.();
  }, [visible, onRefreshHistory]);

  const usageText = useMemo(() => {
    if (!inviteCode) return '-';
    return `${inviteCode.used_count || 0}/${inviteCode.max_uses || 0}`;
  }, [inviteCode]);

  const columns = useMemo(
    () => [
      {
        title: t('邀请码'),
        dataIndex: 'code',
        key: 'code',
        render: (value) => <Text copyable>{value}</Text>,
      },
      {
        title: t('状态'),
        dataIndex: 'status',
        key: 'status',
        render: (value) => renderStatus(value, t),
      },
      {
        title: t('使用情况'),
        key: 'usage',
        render: (_, record) => (
          <Text>{`${record.used_count || 0}/${record.max_uses || 0}`}</Text>
        ),
      },
      {
        title: t('过期时间'),
        dataIndex: 'expires_at',
        key: 'expires_at',
        render: (value) => <Text>{timestamp2string(value)}</Text>,
      },
    ],
    [t],
  );

  const handleSave = () => {
    onSaveRules?.({
      max_uses: Math.max(1, Math.floor(maxUses || 1)),
      expires_at: getExpireAtByDays(expireDays),
    });
  };

  const handleRefresh = () => {
    onRefreshCode?.(Math.max(4, Math.min(10, Math.floor(refreshLength || 8))));
  };

  return (
    <Modal
      title={t('管理邀请码')}
      visible={visible}
      onCancel={onCancel}
      footer={null}
      size='large'
      centered
    >
      <div className='space-y-4'>
        <div className='grid grid-cols-1 md:grid-cols-4 gap-4'>
          <div>
            <div className='text-xs text-gray-500'>{t('当前邀请码')}</div>
            <Text strong copyable>
              {inviteCode?.code || '-'}
            </Text>
          </div>
          <div>
            <div className='text-xs text-gray-500'>{t('使用情况')}</div>
            <Text strong>{usageText}</Text>
          </div>
          <div>
            <div className='text-xs text-gray-500'>{t('过期时间')}</div>
            <Text strong>{timestamp2string(inviteCode?.expires_at)}</Text>
          </div>
          <div>
            <div className='text-xs text-gray-500'>{t('状态')}</div>
            {renderStatus(inviteCode?.status, t)}
          </div>
        </div>

        <div className='grid grid-cols-1 md:grid-cols-2 gap-4'>
          <div>
            <div className='mb-2 text-sm'>{t('最大使用次数')}</div>
            <InputNumber
              min={1}
              value={maxUses}
              onChange={(value) => setMaxUses(Number(value) || 1)}
              style={{ width: '100%' }}
            />
          </div>
          <div>
            <div className='mb-2 text-sm'>{t('有效天数')}</div>
            <InputNumber
              min={1}
              value={expireDays}
              onChange={(value) => setExpireDays(Number(value) || 1)}
              style={{ width: '100%' }}
            />
          </div>
          <div className='md:col-span-2'>
            <div className='mb-2 text-sm'>{t('刷新邀请码长度')}</div>
            <InputNumber
              min={4}
              max={10}
              value={refreshLength}
              onChange={(value) =>
                setRefreshLength(Math.max(4, Math.min(10, Math.floor(Number(value) || 8))))
              }
              style={{ width: '100%' }}
            />
          </div>
        </div>

        <Text type='tertiary'>
          {t('保存规则会立即更新当前邀请码。刷新会生成新码并让旧码立刻失效。')}
        </Text>

        <div className='flex items-center justify-between'>
          <div>
            <div className='text-sm font-medium'>{t('邀请码历史')}</div>
            <div className='text-xs text-gray-500'>
              {t('当历史保留开启时，旧邀请码会显示在这里。')}
            </div>
          </div>
          <Button onClick={() => onRefreshHistory?.()} loading={historyLoading}>
            {t('刷新历史')}
          </Button>
        </div>

        <Table
          rowKey='code'
          columns={columns}
          dataSource={inviteHistory}
          loading={historyLoading}
          pagination={false}
        />

        <div className='flex justify-end gap-2'>
          <Space>
            <Button onClick={handleRefresh} loading={refreshing}>
              {t('刷新邀请码')}
            </Button>
            <Button type='primary' onClick={handleSave} loading={saving}>
              {t('保存邀请码设置')}
            </Button>
          </Space>
        </div>
      </div>
    </Modal>
  );
};

export default InviteCodeModal;
