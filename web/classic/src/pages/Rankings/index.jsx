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

import React, { useContext, useEffect, useMemo, useState } from 'react';
import { Button, Card, DatePicker, Empty, Tabs, TabPane, Tag, Typography } from '@douyinfe/semi-ui';
import {
  IllustrationNoResult,
  IllustrationNoResultDark,
} from '@douyinfe/semi-illustrations';
import { useTranslation } from 'react-i18next';
import CardTable from '../../components/common/ui/CardTable';
import { API, renderQuota, showError, timestamp2string } from '../../helpers';
import { UserContext } from '../../context/User';

const BALANCE_METRIC = 'balance';
const INVITES_METRIC = 'invites';
const CONSUMPTION_METRIC = 'consumption';
const TOTAL_PERIOD = 'total';
const DAILY_PERIOD = 'daily';
const TEN_MINUTES_MS = 10 * 60 * 1000;
const EMPTY_SELF_STATS = {
  balanceTotal: { value: null, rank: null },
  consumptionDaily: { value: null, rank: null },
  consumptionTotal: { value: null, rank: null },
  invitesDaily: { value: null, rank: null },
  invitesTotal: { value: null, rank: null },
};

function pad2(num) {
  return String(num).padStart(2, '0');
}

function formatDateValue(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    return '';
  }
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`;
}

function parseDateValue(raw) {
  if (!raw || typeof raw !== 'string') {
    return null;
  }
  const matched = raw.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!matched) {
    return null;
  }
  const date = new Date(Number(matched[1]), Number(matched[2]) - 1, Number(matched[3]));
  if (formatDateValue(date) !== raw) {
    return null;
  }
  return date;
}

function resolveDateString(value, dateString) {
  if (typeof dateString === 'string' && dateString) {
    return dateString;
  }
  if (!value) {
    return '';
  }
  if (value instanceof Date) {
    return formatDateValue(value);
  }
  if (typeof value === 'string') {
    return value.slice(0, 10);
  }
  if (typeof value === 'object' && typeof value.toDate === 'function') {
    return formatDateValue(value.toDate());
  }
  return '';
}

function getTodayDateString() {
  return formatDateValue(new Date());
}

function isTodayDateString(value) {
  return value === getTodayDateString();
}

function getMsUntilNextTenMinuteBoundary() {
  const now = new Date();
  const next = new Date(now);
  next.setSeconds(0, 0);
  next.setMinutes(Math.floor(now.getMinutes() / 10) * 10 + 10);
  return next.getTime() - now.getTime();
}

const Rankings = () => {
  const { t } = useTranslation();
  const [userState] = useContext(UserContext);

  const [metric, setMetric] = useState(BALANCE_METRIC);
  const [period, setPeriod] = useState(TOTAL_PERIOD);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [visibility, setVisibility] = useState('public');
  const [authOnlyError, setAuthOnlyError] = useState(false);
  const [selfStats, setSelfStats] = useState(EMPTY_SELF_STATS);
  const [selfStatsLoading, setSelfStatsLoading] = useState(false);
  const [selectedDate, setSelectedDate] = useState(() => getTodayDateString());

  const fetchRankings = async (nextMetric, nextPeriod, nextDate) => {
    setLoading(true);
    setAuthOnlyError(false);
    try {
      const res = await API.get('/api/rankings', {
        params: {
          scope: 'users',
          metric: nextMetric,
          period: nextPeriod,
          date: nextDate || undefined,
        },
        skipErrorHandler: true,
      });

      const { success, message, data } = res.data || {};
      if (!success) {
        showError(message || t('排行榜加载失败'));
        setItems([]);
        return;
      }

      setItems(Array.isArray(data?.items) ? data.items : []);
      setUpdatedAt(data?.updated_at || null);
      setVisibility(data?.visibility === 'auth-only' ? 'auth-only' : 'public');
    } catch (error) {
      const status = error?.response?.status;
      const code = error?.response?.data?.code;
      if (status === 401 && code === 'AUTH_NOT_LOGGED_IN') {
        setAuthOnlyError(true);
        setItems([]);
      } else {
        showError(error);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchRankings(metric, period, selectedDate);
  }, [metric, period, selectedDate]);

  useEffect(() => {
    if (!isTodayDateString(selectedDate)) {
      return undefined;
    }

    let timeoutId;
    let intervalId;

    const setupAlignedRefresh = () => {
      const ms = getMsUntilNextTenMinuteBoundary();
      timeoutId = window.setTimeout(() => {
        void fetchRankings(metric, period, selectedDate);
        intervalId = window.setInterval(() => {
          void fetchRankings(metric, period, selectedDate);
        }, TEN_MINUTES_MS);
      }, ms > 0 ? ms : TEN_MINUTES_MS);
    };

    setupAlignedRefresh();
    return () => {
      if (timeoutId) window.clearTimeout(timeoutId);
      if (intervalId) window.clearInterval(intervalId);
    };
  }, [metric, period, selectedDate]);

  const isBalanceMetric = metric === BALANCE_METRIC;
  const isLoggedIn = Boolean(userState?.user?.id);
  const topTenItems = items.slice(0, 10);

  const valueTitle = isBalanceMetric
    ? t('余额')
    : metric === INVITES_METRIC
      ? t('邀请人数')
      : t('消耗额度');

  const columns = useMemo(() => {
    return [
      {
        title: t('排名'),
        dataIndex: 'rank',
        key: 'rank',
        width: 100,
        render: (value) => <RankTag value={value} />,
      },
      {
        title: t('用户名'),
        dataIndex: 'username',
        key: 'username',
        render: (value, record) => (
          <div className='flex flex-col'>
            <span className='font-semibold'>{record.display_name || value || '-'}</span>
            {record.display_name && value ? (
              <Typography.Text type='tertiary' size='small'>
                @{value}
              </Typography.Text>
            ) : null}
          </div>
        ),
      },
      {
        title: valueTitle,
        dataIndex: 'value',
        key: 'value',
        align: 'right',
        render: (value) =>
          isBalanceMetric || metric === CONSUMPTION_METRIC
            ? renderQuota(Number(value || 0))
            : Number(value || 0),
      },
    ];
  }, [isBalanceMetric, metric, t, valueTitle]);

  const pageTitle = t('排行榜');
  const pageDescription = t('查看用户余额、邀请人数和消耗额度的实时排名');
  const extractSelfStat = (list) => {
    const myUserId = Number(userState?.user?.id || 0);
    if (!myUserId || !Array.isArray(list)) {
      return { value: null, rank: null };
    }
    const matched = list.find((item) => Number(item?.user_id) === myUserId);
    if (!matched) {
      return { value: null, rank: null };
    }
    return { value: matched.value, rank: matched.rank };
  };

  useEffect(() => {
    if (!isLoggedIn) {
      setSelfStats(EMPTY_SELF_STATS);
      setSelfStatsLoading(false);
      return;
    }

    let cancelled = false;
    const loadSelfStats = async () => {
      setSelfStatsLoading(true);
      try {
        const requests = [
          API.get('/api/rankings', {
            params: { scope: 'users', metric: BALANCE_METRIC, period: TOTAL_PERIOD, date: selectedDate || undefined },
            skipErrorHandler: true,
          }),
          API.get('/api/rankings', {
            params: { scope: 'users', metric: CONSUMPTION_METRIC, period: DAILY_PERIOD, date: selectedDate || undefined },
            skipErrorHandler: true,
          }),
          API.get('/api/rankings', {
            params: { scope: 'users', metric: CONSUMPTION_METRIC, period: TOTAL_PERIOD, date: selectedDate || undefined },
            skipErrorHandler: true,
          }),
          API.get('/api/rankings', {
            params: { scope: 'users', metric: INVITES_METRIC, period: DAILY_PERIOD, date: selectedDate || undefined },
            skipErrorHandler: true,
          }),
          API.get('/api/rankings', {
            params: { scope: 'users', metric: INVITES_METRIC, period: TOTAL_PERIOD, date: selectedDate || undefined },
            skipErrorHandler: true,
          }),
        ];
        const [balanceRes, consumptionDailyRes, consumptionTotalRes, invitesDailyRes, invitesTotalRes] =
          await Promise.all(requests);

        if (cancelled) return;

        setSelfStats({
          balanceTotal: extractSelfStat(balanceRes?.data?.data?.items),
          consumptionDaily: extractSelfStat(consumptionDailyRes?.data?.data?.items),
          consumptionTotal: extractSelfStat(consumptionTotalRes?.data?.data?.items),
          invitesDaily: extractSelfStat(invitesDailyRes?.data?.data?.items),
          invitesTotal: extractSelfStat(invitesTotalRes?.data?.data?.items),
        });
      } catch (error) {
        if (!cancelled) {
          setSelfStats(EMPTY_SELF_STATS);
        }
      } finally {
        if (!cancelled) {
          setSelfStatsLoading(false);
        }
      }
    };

    void loadSelfStats();

    if (!isTodayDateString(selectedDate)) {
      return () => {
        cancelled = true;
      };
    }

    const ms = getMsUntilNextTenMinuteBoundary();
    let timeoutId;
    let intervalId;
    timeoutId = window.setTimeout(() => {
      void loadSelfStats();
      intervalId = window.setInterval(() => {
        void loadSelfStats();
      }, TEN_MINUTES_MS);
    }, ms > 0 ? ms : TEN_MINUTES_MS);

    return () => {
      cancelled = true;
      if (timeoutId) window.clearTimeout(timeoutId);
      if (intervalId) window.clearInterval(intervalId);
    };
  }, [isLoggedIn, selectedDate, userState?.user?.id]);

  return (
    <div className='mt-[60px] px-2'>
      <Card
        className='!rounded-2xl'
        title={
          <div className='flex flex-col gap-1'>
            <span className='text-base font-semibold'>{pageTitle}</span>
            <Typography.Text type='tertiary' size='small'>
              {pageDescription}
            </Typography.Text>
          </div>
        }
      >
        <div className='mt-1 rounded-xl border border-dashed p-3'>
          <div className='flex flex-wrap items-center justify-between gap-2'>
            <Tabs
              type='button'
              activeKey={metric}
              onChange={(key) => {
                if (key === BALANCE_METRIC) {
                  setMetric(BALANCE_METRIC);
                  setPeriod(TOTAL_PERIOD);
                  return;
                }
                if (key === INVITES_METRIC) {
                  setMetric(INVITES_METRIC);
                  return;
                }
                setMetric(CONSUMPTION_METRIC);
              }}
            >
              <TabPane tab={t('余额')} itemKey={BALANCE_METRIC} />
              <TabPane tab={t('邀请人数')} itemKey={INVITES_METRIC} />
              <TabPane tab={t('消耗额度')} itemKey={CONSUMPTION_METRIC} />
            </Tabs>

            <div className='flex items-center gap-2'>
              <DatePicker
                type='date'
                size='small'
                format='yyyy-MM-dd'
                value={parseDateValue(selectedDate) || undefined}
                inputReadOnly={true}
                showClear={false}
                onChange={(value, dateString) => {
                  const resolved = resolveDateString(value, dateString);
                  if (resolved) {
                    setSelectedDate(resolved);
                  }
                }}
              />
              <Button
                size='small'
                theme={isTodayDateString(selectedDate) ? 'light' : 'borderless'}
                type={isTodayDateString(selectedDate) ? 'primary' : 'tertiary'}
                onClick={() => setSelectedDate(getTodayDateString())}
              >
                {t('今天')}
              </Button>
              {updatedAt ? (
                <Typography.Text type='tertiary' size='small'>
                  {t('更新时间')}: {timestamp2string(updatedAt)}
                </Typography.Text>
              ) : null}
            </div>
          </div>

          {!isBalanceMetric ? (
            <Tabs
              type='button'
              activeKey={period}
              className='mt-2'
              onChange={(key) => {
                if (key === DAILY_PERIOD) {
                  setPeriod(DAILY_PERIOD);
                } else {
                  setPeriod(TOTAL_PERIOD);
                }
              }}
            >
              <TabPane tab={t('总榜')} itemKey={TOTAL_PERIOD} />
              <TabPane tab={t('日榜')} itemKey={DAILY_PERIOD} />
            </Tabs>
          ) : null}
        </div>

        {visibility === 'auth-only' && (
          <div className='mt-3'>
            <Typography.Text type='tertiary'>
              {t('开启后未登录用户无法访问排行榜')}
            </Typography.Text>
          </div>
        )}

        {authOnlyError ? (
          <div className='py-8'>
            <Empty
              image={<IllustrationNoResult style={{ width: 150, height: 150 }} />}
              darkModeImage={
                <IllustrationNoResultDark style={{ width: 150, height: 150 }} />
              }
              title={t('需要登录访问')}
              description={t('开启后未登录用户无法访问排行榜')}
            />
          </div>
        ) : (
          <div
            className={
              isLoggedIn
                ? 'mt-3 grid gap-3 xl:grid-cols-[minmax(0,1fr)_280px]'
                : 'mt-3 grid gap-3'
            }
          >
            <Card className='!rounded-xl overflow-hidden border-0 shadow-sm' bodyStyle={{ padding: 0 }}>
              <CardTable
                columns={columns}
                dataSource={topTenItems}
                loading={loading}
                rowKey={(record) => record.user_id || record.rank}
                hidePagination={true}
                empty={
                  <Empty
                    image={<IllustrationNoResult style={{ width: 150, height: 150 }} />}
                    darkModeImage={
                      <IllustrationNoResultDark style={{ width: 150, height: 150 }} />
                    }
                    description={t('暂无数据')}
                    style={{ padding: 30 }}
                  />
                }
              />
            </Card>

            {isLoggedIn && (
              <Card
                className='!rounded-xl border-0 shadow-sm'
                title={<span className='text-sm font-semibold'>{t('我的排行摘要')}</span>}
                bodyStyle={{ padding: 12 }}
              >
                {selfStatsLoading ? (
                  <Typography.Text type='tertiary'>...</Typography.Text>
                ) : (
                  <div className='space-y-2'>
                    {[
                      { key: 'balanceTotal', metricLabel: t('余额'), periodLabel: t('总榜'), quota: true },
                      { key: 'consumptionDaily', metricLabel: t('消耗额度'), periodLabel: t('日榜'), quota: true },
                      { key: 'consumptionTotal', metricLabel: t('消耗额度'), periodLabel: t('总榜'), quota: true },
                      { key: 'invitesDaily', metricLabel: t('邀请人数'), periodLabel: t('日榜'), quota: false },
                      { key: 'invitesTotal', metricLabel: t('邀请人数'), periodLabel: t('总榜'), quota: false },
                    ].map((item) => {
                      const stat = selfStats[item.key] || { value: null, rank: null };
                      return (
                        <div
                          key={item.key}
                          className='flex items-center justify-between rounded-lg border border-dashed px-3 py-2'
                        >
                          <div className='min-w-0'>
                            <div className='truncate text-sm font-medium'>
                              {item.metricLabel}（{item.periodLabel}）
                            </div>
                            <Typography.Text type='tertiary' size='small'>
                              {t('当前排名')}: {stat.rank == null ? t('未上榜') : `#${stat.rank}`}
                            </Typography.Text>
                          </div>
                          <div className='text-sm font-semibold tabular-nums'>
                            {stat.value == null
                              ? t('暂无数据')
                              : item.quota
                                ? renderQuota(Number(stat.value || 0))
                                : Number(stat.value || 0)}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </Card>
            )}
          </div>
        )}
      </Card>
    </div>
  );
};

function RankTag({ value }) {
  if (value === 1) return <Tag color='amber'>{`#${value}`}</Tag>;
  if (value === 2) return <Tag color='indigo'>{`#${value}`}</Tag>;
  if (value === 3) return <Tag color='orange'>{`#${value}`}</Tag>;
  return <Tag color='white'>{`#${value}`}</Tag>;
}

export default Rankings;
