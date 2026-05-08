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

import React, { useState, useCallback, useEffect, useRef } from 'react';
import axios from 'axios';
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

const normalizeProfileBins = (bins) => {
  const raw = Array.isArray(bins) ? bins : [];
  if (raw.length === 48) {
    return raw.map((item) => {
      const num = Number(item);
      return Number.isFinite(num) ? Math.max(0, num) : 0;
    });
  }
  if (raw.length === 24) {
    return raw
      .map((item) => {
        const num = Number(item);
        return Number.isFinite(num) ? Math.max(0, num) : 0;
      })
      .flatMap((item) => [item, item]);
  }
  const normalized = raw.map((item) => {
    const num = Number(item);
    return Number.isFinite(num) ? Math.max(0, num) : 0;
  });
  while (normalized.length < 48) {
    normalized.push(0);
  }
  return normalized.slice(0, 48);
};

const hasTemporalProfileData = (profile) => {
  if (!profile || typeof profile !== 'object') return false;
  const sampleCount = Number(profile.sample_count || 0);
  if (sampleCount > 0) return true;
  const rawBins = profile.profile_bins;
  if (!Array.isArray(rawBins) || rawBins.length === 0) return false;
  return rawBins.some((item) => Number(item || 0) > 0);
};

const getTemporalPeakLabel = (profile) => {
  if (!hasTemporalProfileData(profile)) return '-';
  const bins = normalizeProfileBins(profile?.profile_bins || []);
  if (!bins.length) return '-';
  let maxIdx = 0;
  for (let i = 1; i < bins.length; i++) {
    if ((bins[i] || 0) > (bins[maxIdx] || 0)) maxIdx = i;
  }
  return getHalfHourLabel(maxIdx);
};

const getTemporalConcentration = (profile) => {
  if (!hasTemporalProfileData(profile)) return '-';
  const bins = normalizeProfileBins(profile?.profile_bins || []);
  if (!bins.length) return '-';
  const max = bins.reduce((m, v) => Math.max(m, v || 0), 0);
  return `${Math.round(max * 100)}%`;
};

const getHalfHourLabel = (idx) => {
  const hour = Math.floor(idx / 2);
  const minute = idx % 2 === 0 ? '00' : '30';
  return `${String(hour).padStart(2, '0')}:${minute}`;
};

const getTemporalOverlapRatio = (profileA, profileB) => {
  if (!hasTemporalProfileData(profileA) || !hasTemporalProfileData(profileB)) {
    return null;
  }
  const a = normalizeProfileBins(profileA?.profile_bins || []);
  const b = normalizeProfileBins(profileB?.profile_bins || []);
  let minSum = 0;
  let maxSum = 0;
  for (let i = 0; i < 48; i++) {
    minSum += Math.min(a[i], b[i]);
    maxSum += Math.max(a[i], b[i]);
  }
  if (maxSum <= 0) return null;
  return minSum / maxSum;
};

const getTierStyle = (tier) => {
  const normalized = String(tier || '').toLowerCase();
  const map = {
    tier1: { label: 'Tier 1', color: 'red' },
    tier2: { label: 'Tier 2', color: 'orange' },
    tier3: { label: 'Tier 3', color: 'yellow' },
    tier4: { label: 'Tier 4', color: 'blue' },
    fallback: { label: 'Fallback', color: 'grey' },
  };
  return map[normalized] || map.fallback;
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
  const [networkProfile, setNetworkProfile] = useState(null);
  const [temporalProfile, setTemporalProfile] = useState(null);
  const [profileLoading, setProfileLoading] = useState(false);
  const [dashboardStats, setDashboardStats] = useState(null);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [assocTemporalProfiles, setAssocTemporalProfiles] = useState({});
  const [assocNetworkProfiles, setAssocNetworkProfiles] = useState({});
  const [assocProfileLoading, setAssocProfileLoading] = useState({});
  const [associationDetails, setAssociationDetails] = useState({});
  const [associationDetailLoading, setAssociationDetailLoading] = useState({});
  const activeUserIdRef = useRef(safeInt(initialUserId));
  const queryRequestSeqRef = useRef(0);
  const queryAbortControllerRef = useRef(null);
  const profileRequestSeqRef = useRef(0);
  const dashboardRequestSeqRef = useRef(0);
  const assocProfileRequestSeqRef = useRef({});
  const associationDetailRequestSeqRef = useRef({});
  const targetDevicesRequestSeqRef = useRef(0);
  const deviceProfilesRequestSeqRef = useRef({});

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
      behavior: '🧠',
      environment: '⚙️',
    };
    return map[cat] || '📊';
  };

  const resetAssociationState = useCallback(() => {
    if (queryAbortControllerRef.current) {
      queryAbortControllerRef.current.abort();
      queryAbortControllerRef.current = null;
    }
    setLoading(false);
    setResult(null);
    setQueried(false);
    setDeviceProfiles({});
    setDeviceLoading({});
    setExpandedDevices({});
    setTargetDevices([]);
    setTargetDevicesLoading(false);
    setShowTargetDevices(false);
    setSelectedProfileId(null);
    setSelectedProfileInfo(null);
    setNetworkProfile(null);
    setTemporalProfile(null);
    setProfileLoading(false);
    setDashboardStats(null);
    setDashboardLoading(false);
    setAssocTemporalProfiles({});
    setAssocNetworkProfiles({});
    setAssocProfileLoading({});
    setAssociationDetails({});
    setAssociationDetailLoading({});
    queryRequestSeqRef.current += 1;
    profileRequestSeqRef.current += 1;
    dashboardRequestSeqRef.current += 1;
    assocProfileRequestSeqRef.current = {};
    associationDetailRequestSeqRef.current = {};
    targetDevicesRequestSeqRef.current += 1;
    deviceProfilesRequestSeqRef.current = {};
  }, []);

  useEffect(() => {
    const nextUserId =
      initialUserId === undefined || initialUserId === null
        ? ''
        : String(initialUserId);
    setInputUserId((prev) => (String(prev) === nextUserId ? prev : nextUserId));
  }, [initialUserId]);

  useEffect(() => {
    activeUserIdRef.current = safeInt(inputUserId);
    resetAssociationState();
  }, [inputUserId, resetAssociationState]);

  useEffect(() => {
    return () => {
      if (queryAbortControllerRef.current) {
        queryAbortControllerRef.current.abort();
        queryAbortControllerRef.current = null;
      }
    };
  }, []);

  const fetchNetworkAndTemporalProfile = useCallback(
    async (userIdSnapshot = safeInt(inputUserId)) => {
      const safeUserId = safeInt(userIdSnapshot);
      if (!safeUserId) {
        setNetworkProfile(null);
        setTemporalProfile(null);
        return;
      }

      const requestId = profileRequestSeqRef.current + 1;
      profileRequestSeqRef.current = requestId;
      setProfileLoading(true);
      try {
        const [networkRes, temporalRes] = await Promise.all([
          API.get(`/api/admin/fingerprint/user/${safeUserId}/network`),
          API.get(`/api/admin/fingerprint/user/${safeUserId}/temporal`),
        ]);

        if (
          requestId !== profileRequestSeqRef.current ||
          activeUserIdRef.current !== safeUserId
        ) {
          return;
        }

        const nextNetworkProfile = networkRes.data.success
          ? networkRes.data.data || null
          : null;
        const nextTemporalProfile = temporalRes.data.success
          ? temporalRes.data.data || null
          : null;

        setNetworkProfile(nextNetworkProfile);
        setTemporalProfile(nextTemporalProfile);
      } catch {
        if (
          requestId !== profileRequestSeqRef.current ||
          activeUserIdRef.current !== safeUserId
        ) {
          return;
        }
        setNetworkProfile(null);
        setTemporalProfile(null);
      } finally {
        if (
          requestId === profileRequestSeqRef.current &&
          activeUserIdRef.current === safeUserId
        ) {
          setProfileLoading(false);
        }
      }
    },
    [inputUserId],
  );

  const fetchDashboardStats = useCallback(
    async (userIdSnapshot = safeInt(inputUserId)) => {
      const safeUserId = safeInt(userIdSnapshot);
      if (!safeUserId) {
        setDashboardStats(null);
        return;
      }

      const requestId = dashboardRequestSeqRef.current + 1;
      dashboardRequestSeqRef.current = requestId;
      setDashboardLoading(true);
      try {
        const res = await API.get('/api/admin/fingerprint/dashboard');

        if (
          requestId !== dashboardRequestSeqRef.current ||
          activeUserIdRef.current !== safeUserId
        ) {
          return;
        }

        setDashboardStats(res.data.success ? res.data.data || null : null);
      } catch {
        if (
          requestId !== dashboardRequestSeqRef.current ||
          activeUserIdRef.current !== safeUserId
        ) {
          return;
        }
        setDashboardStats(null);
      } finally {
        if (
          requestId === dashboardRequestSeqRef.current &&
          activeUserIdRef.current === safeUserId
        ) {
          setDashboardLoading(false);
        }
      }
    },
    [inputUserId],
  );

  const fetchAssociationProfiles = useCallback(
    async (assocUserId) => {
      const safeAssocUserId = safeInt(assocUserId);
      const targetUserId = safeInt(inputUserId);
      if (!safeAssocUserId || !targetUserId) {
        return;
      }

      if (assocProfileLoading[safeAssocUserId]) {
        return;
      }

      const hasTemporalCache = Object.prototype.hasOwnProperty.call(
        assocTemporalProfiles,
        safeAssocUserId,
      );
      const hasNetworkCache = Object.prototype.hasOwnProperty.call(
        assocNetworkProfiles,
        safeAssocUserId,
      );
      if (hasTemporalCache && hasNetworkCache) {
        return;
      }

      const requestId =
        (assocProfileRequestSeqRef.current[safeAssocUserId] || 0) + 1;
      assocProfileRequestSeqRef.current = {
        ...assocProfileRequestSeqRef.current,
        [safeAssocUserId]: requestId,
      };

      setAssocProfileLoading((prev) => ({ ...prev, [safeAssocUserId]: true }));
      try {
        const [networkRes, temporalRes] = await Promise.all([
          API.get(`/api/admin/fingerprint/user/${safeAssocUserId}/network`),
          API.get(`/api/admin/fingerprint/user/${safeAssocUserId}/temporal`),
        ]);

        if (
          activeUserIdRef.current !== targetUserId ||
          assocProfileRequestSeqRef.current[safeAssocUserId] !== requestId
        ) {
          return;
        }

        if (networkRes.data.success) {
          setAssocNetworkProfiles((prev) => ({
            ...prev,
            [safeAssocUserId]: networkRes.data.data || null,
          }));
        }
        if (temporalRes.data.success) {
          setAssocTemporalProfiles((prev) => ({
            ...prev,
            [safeAssocUserId]: temporalRes.data.data || null,
          }));
        }
        if (!networkRes.data.success || !temporalRes.data.success) {
          showError(
            networkRes.data.message ||
              temporalRes.data.message ||
              t('加载关联用户画像失败'),
          );
        }
      } catch {
        if (
          activeUserIdRef.current !== targetUserId ||
          assocProfileRequestSeqRef.current[safeAssocUserId] !== requestId
        ) {
          return;
        }

        showError(t('加载关联用户画像失败'));
      } finally {
        if (
          activeUserIdRef.current === targetUserId &&
          assocProfileRequestSeqRef.current[safeAssocUserId] === requestId
        ) {
          setAssocProfileLoading((prev) => ({
            ...prev,
            [safeAssocUserId]: false,
          }));
        }
      }
    },
    [
      inputUserId,
      assocNetworkProfiles,
      assocProfileLoading,
      assocTemporalProfiles,
    ],
  );

  const fetchAssociationDetails = useCallback(
    async (assocUserId) => {
      const safeAssocUserId = safeInt(assocUserId);
      const targetUserId = safeInt(inputUserId);
      if (!safeAssocUserId || !targetUserId) {
        return null;
      }

      if (associationDetailLoading[safeAssocUserId]) {
        return associationDetails[safeAssocUserId] || null;
      }

      if (
        Object.prototype.hasOwnProperty.call(
          associationDetails,
          safeAssocUserId,
        )
      ) {
        return associationDetails[safeAssocUserId] || null;
      }

      const requestId =
        (associationDetailRequestSeqRef.current[safeAssocUserId] || 0) + 1;
      associationDetailRequestSeqRef.current = {
        ...associationDetailRequestSeqRef.current,
        [safeAssocUserId]: requestId,
      };

      setAssociationDetailLoading((prev) => ({
        ...prev,
        [safeAssocUserId]: true,
      }));

      try {
        let url = `/api/admin/fingerprint/user/${targetUserId}/associations?min_confidence=${minConfidence}&limit=20&refresh=false&mode=full&include_details=true&include_shared_ips=true&candidate_user_id=${safeAssocUserId}`;
        const safeProfileId = safeInt(selectedProfileId);
        if (safeProfileId) {
          url += `&device_profile_id=${safeProfileId}`;
        }

        const res = await API.get(url);
        if (
          activeUserIdRef.current !== targetUserId ||
          associationDetailRequestSeqRef.current[safeAssocUserId] !== requestId
        ) {
          return null;
        }

        if (!res.data.success) {
          showError(res.data.message || t('加载关联详情失败'));
          return null;
        }

        const detailAssoc = (res.data.data?.associations || []).find(
          (item) => safeInt(item?.user?.id) === safeAssocUserId,
        );
        const normalizedDetail = detailAssoc || null;

        setAssociationDetails((prev) => ({
          ...prev,
          [safeAssocUserId]: normalizedDetail,
        }));

        return normalizedDetail;
      } catch (e) {
        if (
          activeUserIdRef.current !== targetUserId ||
          associationDetailRequestSeqRef.current[safeAssocUserId] !== requestId
        ) {
          return null;
        }

        showError(e.message || t('加载关联详情失败'));
        return null;
      } finally {
        if (
          activeUserIdRef.current === targetUserId &&
          associationDetailRequestSeqRef.current[safeAssocUserId] === requestId
        ) {
          setAssociationDetailLoading((prev) => ({
            ...prev,
            [safeAssocUserId]: false,
          }));
        }
      }
    },
    [
      associationDetailLoading,
      associationDetails,
      inputUserId,
      minConfidence,
      selectedProfileId,
      t,
    ],
  );

  const queryAssociations = useCallback(
    async (refresh = false, profileId = selectedProfileId) => {
      const safeUserId = safeInt(inputUserId);
      if (!safeUserId) {
        showError(t('请输入有效的用户ID（纯数字）'));
        return;
      }

      activeUserIdRef.current = safeUserId;
      const requestId = queryRequestSeqRef.current + 1;
      queryRequestSeqRef.current = requestId;

      setAssociationDetails({});
      setAssociationDetailLoading({});
      associationDetailRequestSeqRef.current = {};

      setLoading(true);
      if (queryAbortControllerRef.current) {
        queryAbortControllerRef.current.abort();
      }
      const abortController = new AbortController();
      queryAbortControllerRef.current = abortController;
      try {
        let url = `/api/admin/fingerprint/user/${safeUserId}/associations?min_confidence=${minConfidence}&limit=20&refresh=${refresh}&mode=fast&include_details=false&include_shared_ips=false`;
        const safeProfileId = safeInt(profileId);
        if (safeProfileId) {
          url += `&device_profile_id=${safeProfileId}`;
        }
        const res = await API.get(url, {
          disableDuplicate: true,
          skipErrorHandler: true,
          signal: abortController.signal,
        });

        if (
          requestId !== queryRequestSeqRef.current ||
          activeUserIdRef.current !== safeUserId
        ) {
          return;
        }

        if (res.data.success) {
          setResult(res.data.data);
          setQueried(true);
          fetchNetworkAndTemporalProfile(safeUserId);
          fetchDashboardStats(safeUserId);
        } else {
          showError(res.data.message || t('查询失败'));
        }
      } catch (e) {
        if (axios.isCancel(e) || e?.code === 'ERR_CANCELED') {
          return;
        }
        if (
          requestId === queryRequestSeqRef.current &&
          activeUserIdRef.current === safeUserId
        ) {
          if (e) {
            showError(e);
          } else {
            showError(t('网络错误'));
          }
        }
      } finally {
        if (queryAbortControllerRef.current === abortController) {
          queryAbortControllerRef.current = null;
        }
        if (
          requestId === queryRequestSeqRef.current &&
          activeUserIdRef.current === safeUserId
        ) {
          setLoading(false);
        }
      }
    },
    [
      inputUserId,
      minConfidence,
      t,
      selectedProfileId,
      fetchNetworkAndTemporalProfile,
      fetchDashboardStats,
    ],
  );

  // ★ 新增: 获取目标用户自己的设备列表
  const fetchTargetDevices = useCallback(async () => {
    const safeUserId = safeInt(inputUserId);
    if (!safeUserId) return;

    setShowTargetDevices((prev) => !prev);

    // 已加载过就不重复请求
    if (targetDevices.length > 0) return;

    const requestId = targetDevicesRequestSeqRef.current + 1;
    targetDevicesRequestSeqRef.current = requestId;
    setTargetDevicesLoading(true);
    try {
      const res = await API.get(
        `/api/admin/fingerprint/user/${safeUserId}/devices`,
      );
      if (
        requestId !== targetDevicesRequestSeqRef.current ||
        activeUserIdRef.current !== safeUserId
      ) {
        return;
      }
      if (res.data.success) {
        setTargetDevices(res.data.data || []);
      } else {
        setTargetDevices([]);
      }
    } catch {
      if (
        requestId !== targetDevicesRequestSeqRef.current ||
        activeUserIdRef.current !== safeUserId
      ) {
        return;
      }
      setTargetDevices([]);
    } finally {
      if (
        requestId === targetDevicesRequestSeqRef.current &&
        activeUserIdRef.current === safeUserId
      ) {
        setTargetDevicesLoading(false);
      }
    }
  }, [inputUserId, targetDevices.length]);

  const fetchDeviceProfiles = useCallback(
    async (userId) => {
      const safeUserId = safeInt(userId);
      const targetUserId = safeInt(inputUserId);
      if (!safeUserId || !targetUserId) return;
      setExpandedDevices((prev) => {
        const next = { ...prev, [safeUserId]: !prev[safeUserId] };
        if (
          next[safeUserId] &&
          deviceProfiles[safeUserId] === undefined &&
          !deviceLoading[safeUserId]
        ) {
          const requestId =
            (deviceProfilesRequestSeqRef.current[safeUserId] || 0) + 1;
          deviceProfilesRequestSeqRef.current = {
            ...deviceProfilesRequestSeqRef.current,
            [safeUserId]: requestId,
          };
          setDeviceLoading((dl) => ({ ...dl, [safeUserId]: true }));
          API.get(`/api/admin/fingerprint/user/${safeUserId}/devices`)
            .then((res) => {
              if (
                activeUserIdRef.current !== targetUserId ||
                deviceProfilesRequestSeqRef.current[safeUserId] !== requestId
              ) {
                return;
              }
              if (res.data.success) {
                setDeviceProfiles((dp) => ({
                  ...dp,
                  [safeUserId]: res.data.data || [],
                }));
              } else {
                setDeviceProfiles((dp) => ({ ...dp, [safeUserId]: [] }));
              }
            })
            .catch(() => {
              if (
                activeUserIdRef.current !== targetUserId ||
                deviceProfilesRequestSeqRef.current[safeUserId] !== requestId
              ) {
                return;
              }
              setDeviceProfiles((dp) => ({ ...dp, [safeUserId]: [] }));
            })
            .finally(() => {
              if (
                activeUserIdRef.current === targetUserId &&
                deviceProfilesRequestSeqRef.current[safeUserId] === requestId
              ) {
                setDeviceLoading((dl) => ({ ...dl, [safeUserId]: false }));
              }
            });
        }
        return next;
      });
    },
    [deviceProfiles, deviceLoading, inputUserId],
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
        await API.post(`/api/admin/fingerprint/links/${safeLinkId}/review`, {
          action,
          note: '',
        });
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

  const renderTemporalHeatStrip = useCallback(
    (profile, label) => {
      if (!hasTemporalProfileData(profile)) {
        return (
          <div>
            {label && (
              <Text type='tertiary' size='small'>
                {label}
              </Text>
            )}
            <div className='mt-1'>
              <Text type='tertiary' size='small'>
                {t('暂无时序样本')}
              </Text>
            </div>
          </div>
        );
      }

      const normalized = normalizeProfileBins(profile?.profile_bins || []);
      const maxVal = normalized.reduce((acc, cur) => Math.max(acc, cur), 0);
      return (
        <div>
          {label && (
            <Text type='tertiary' size='small'>
              {label}
            </Text>
          )}
          <div className='mt-1'>
            <div className='grid grid-cols-12 gap-[3px]'>
              {normalized.map((value, idx) => {
                const ratio = maxVal > 0 ? value / maxVal : 0;
                const alpha = Math.max(0.12, Math.min(1, ratio));
                return (
                  <div
                    key={`${label || 'temporal'}-${idx}`}
                    className='h-[10px] rounded-sm'
                    style={{
                      backgroundColor: `rgba(34, 197, 94, ${alpha})`,
                    }}
                    title={`${getHalfHourLabel(idx)} · ${(value * 100).toFixed(1)}%`}
                  />
                );
              })}
            </div>
            <div className='mt-1 flex justify-between text-[10px] text-gray-500'>
              <span>00:00</span>
              <span>12:00</span>
              <span>23:30</span>
            </div>
          </div>
        </div>
      );
    },
    [t],
  );

  const renderMutualExclusionTimeline = useCallback(
    (targetProfile, assocProfile) => {
      if (
        !hasTemporalProfileData(targetProfile) ||
        !hasTemporalProfileData(assocProfile)
      ) {
        return (
          <div className='mt-2 rounded-md border border-orange-100 bg-white p-2'>
            <Text size='small' type='tertiary'>
              {t('时序样本不足，无法计算互斥切换时间线')}
            </Text>
          </div>
        );
      }

      const target = normalizeProfileBins(targetProfile?.profile_bins || []);
      const assoc = normalizeProfileBins(assocProfile?.profile_bins || []);
      const segments = target.map((targetVal, idx) => {
        const assocVal = assoc[idx] || 0;
        const targetActive = targetVal > 0;
        const assocActive = assocVal > 0;

        let mode = 'none';
        let color = '#E5E7EB';
        if (targetActive && assocActive) {
          mode = 'both';
          color = '#22C55E';
        } else if (targetActive) {
          mode = 'target_only';
          color = '#3B82F6';
        } else if (assocActive) {
          mode = 'assoc_only';
          color = '#F59E0B';
        }

        return {
          idx,
          mode,
          color,
          targetVal,
          assocVal,
        };
      });

      const counts = segments.reduce(
        (acc, item) => {
          acc[item.mode] += 1;
          return acc;
        },
        { target_only: 0, assoc_only: 0, both: 0, none: 0 },
      );

      return (
        <div className='mt-2 rounded-md border border-orange-100 bg-white p-2'>
          <div className='flex items-center justify-between mb-1'>
            <Text size='small' type='secondary'>
              {t('48 段互斥切换时间线（每段 30 分钟）')}
            </Text>
            <Text size='small' type='tertiary'>
              {t('互斥段')} {counts.target_only + counts.assoc_only}/48
            </Text>
          </div>
          <div className='grid grid-cols-12 gap-[3px]'>
            {segments.map((item) => {
              const label =
                item.mode === 'both'
                  ? t('双方都活跃')
                  : item.mode === 'target_only'
                    ? t('仅目标活跃')
                    : item.mode === 'assoc_only'
                      ? t('仅关联活跃')
                      : t('都不活跃');
              return (
                <div
                  key={`mutual-timeline-${item.idx}`}
                  className='h-[10px] rounded-sm'
                  style={{ backgroundColor: item.color }}
                  title={`${getHalfHourLabel(item.idx)} · ${label} · ${t('目标')}:${(item.targetVal * 100).toFixed(0)}% · ${t('关联')}:${(item.assocVal * 100).toFixed(0)}%`}
                />
              );
            })}
          </div>
          <div className='mt-1 flex justify-between text-[10px] text-gray-500'>
            <span>00:00</span>
            <span>12:00</span>
            <span>23:30</span>
          </div>
          <div className='mt-2 flex flex-wrap gap-1'>
            <Tag size='small' color='blue'>
              {t('仅目标活跃')}: {counts.target_only}
            </Tag>
            <Tag size='small' color='orange'>
              {t('仅关联活跃')}: {counts.assoc_only}
            </Tag>
            <Tag size='small' color='green'>
              {t('双方都活跃')}: {counts.both}
            </Tag>
            <Tag size='small' color='grey'>
              {t('都不活跃')}: {counts.none}
            </Tag>
          </div>
        </div>
      );
    },
    [t],
  );

  const getVpnRiskHints = useCallback(
    (assocSummary, assocDetail) => {
      const hints = [];
      const assocNet = assocNetworkProfiles[assocSummary.user.id];
      const targetRate = Number(networkProfile?.datacenter_rate || 0);
      const assocRate = Number(assocNet?.datacenter_rate || 0);
      const datacenterRatio = Math.max(targetRate, assocRate);
      const sharedIPs = Array.isArray(assocDetail?.shared_ips)
        ? assocDetail.shared_ips
        : [];
      const vpnDims = (assocDetail?.details || []).filter(
        (item) =>
          item.dimension === 'dns_resolver_ip' ||
          item.dimension === 'ip_exact' ||
          item.dimension === 'ip_subnet' ||
          item.dimension === 'webrtc_ip' ||
          item.dimension === 'asn_similarity',
      );

      if (datacenterRatio >= 0.7) {
        hints.push({
          level: 'high',
          text: `${t('机房IP占比高')}: ${Math.round(datacenterRatio * 100)}%`,
        });
      } else if (datacenterRatio >= 0.4) {
        hints.push({
          level: 'medium',
          text: `${t('机房IP占比偏高')}: ${Math.round(datacenterRatio * 100)}%`,
        });
      }

      if (sharedIPs.length >= 2 && datacenterRatio >= 0.3) {
        hints.push({
          level: 'high',
          text: t('共享IP与机房特征同时出现，存在代理池重合风险'),
        });
      }

      const matchedNetSignals = vpnDims.filter((item) => item.matched).length;
      if (matchedNetSignals >= 3) {
        hints.push({
          level: 'medium',
          text: t('网络相关维度命中较多，建议结合ASN与时间模式复核'),
        });
      }

      if (
        (dashboardStats?.vpn_usage_stats?.vpn || 0) > 0 &&
        datacenterRatio >= 0.4
      ) {
        hints.push({
          level: 'low',
          text: t('全局存在VPN样本，当前关联受代理影响概率上升'),
        });
      }

      return hints.slice(0, 3);
    },
    [
      assocNetworkProfiles,
      dashboardStats?.vpn_usage_stats?.vpn,
      networkProfile?.datacenter_rate,
      t,
    ],
  );

  const getSignalSummaryByCategory = useCallback(
    (assocSummary, assocDetail) => {
      const details = Array.isArray(assocDetail?.details)
        ? assocDetail.details
        : [];
      const matchedSet = new Set(
        (assocSummary.matched_dimensions || []).map((item) => String(item)),
      );
      const categoryOrder = ['device', 'network', 'behavior', 'environment'];
      const labels = {
        device: t('设备'),
        network: t('网络'),
        behavior: t('行为'),
        environment: t('环境'),
      };

      return categoryOrder.map((category) => {
        const categoryItems = details.filter(
          (item) => item.category === category,
        );
        const matchedItems = categoryItems.filter(
          (item) => item.matched || matchedSet.has(item.dimension),
        );
        const topSignals = [...categoryItems]
          .sort((a, b) => (b.weight || 0) - (a.weight || 0))
          .slice(0, 3)
          .map((item) => ({
            ...item,
            highlighted: item.matched || matchedSet.has(item.dimension),
          }));

        return {
          category,
          label: labels[category],
          matchedCount: matchedItems.length,
          totalCount: categoryItems.length,
          topSignals,
        };
      });
    },
    [t],
  );

  const buildDeviceColumns = (allowCompare = false) => {
    const columns = [
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
          <Text size='small'>{v ? new Date(v).toLocaleDateString() : '-'}</Text>
        ),
      },
      {
        title: t('最近'),
        dataIndex: 'last_seen_at',
        width: 90,
        render: (v) => (
          <Text size='small'>{v ? new Date(v).toLocaleDateString() : '-'}</Text>
        ),
      },
      {
        title: t('次数'),
        dataIndex: 'seen_count',
        width: 50,
        render: (v) => <Text size='small'>{v}</Text>,
      },
    ];

    if (!allowCompare) {
      return columns;
    }

    return [
      ...columns,
      {
        title: t('操作'),
        width: 80,
        render: (_, row) => {
          const rowProfileId = safeInt(row.id);
          return (
            <Button
              size='small'
              theme='light'
              type={selectedProfileId === rowProfileId ? 'primary' : 'tertiary'}
              disabled={!rowProfileId}
              onClick={() => handleSelectProfile(row)}
            >
              {selectedProfileId === rowProfileId ? t('比对中') : t('比对')}
            </Button>
          );
        },
      },
    ];
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

            <Card
              className='!rounded-xl mb-3'
              bodyStyle={{ padding: '10px 12px' }}
            >
              <div className='flex items-center justify-between mb-2'>
                <Text strong>{t('网络与时序画像')}</Text>
                {profileLoading && <Spin size='small' />}
              </div>
              <div className='grid grid-cols-1 md:grid-cols-2 gap-3'>
                <div className='rounded-lg border border-gray-100 p-2'>
                  <Text type='secondary' size='small'>
                    {t('网络画像')}
                  </Text>
                  <div className='mt-1 text-xs text-gray-700'>
                    <div>
                      {t('历史记录')}: {networkProfile?.history_count ?? '-'}
                    </div>
                    <div>
                      {t('机房IP占比')}:{' '}
                      {networkProfile?.datacenter_rate !== undefined
                        ? `${Math.round(networkProfile.datacenter_rate * 100)}%`
                        : '-'}
                    </div>
                    <div>
                      {t('机房IP次数')}:{' '}
                      {networkProfile?.datacenter_count ?? '-'}
                    </div>
                    <div className='mt-1'>
                      {t('ASN分布')}:{' '}
                      {(networkProfile?.asn_stats || [])
                        .slice(0, 3)
                        .map((s) => `AS${s.asn}(${s.count})`)
                        .join(', ') || '-'}
                    </div>
                  </div>
                </div>
                <div className='rounded-lg border border-gray-100 p-2'>
                  <Text type='secondary' size='small'>
                    {t('时序画像')}
                  </Text>
                  <div className='mt-1 text-xs text-gray-700'>
                    <div>
                      {t('样本数')}: {temporalProfile?.sample_count ?? '-'}
                    </div>
                    <div>
                      {t('高峰时段')}: {getTemporalPeakLabel(temporalProfile)}
                    </div>
                    <div>
                      {t('活跃集中度')}:{' '}
                      {getTemporalConcentration(temporalProfile)}
                    </div>
                  </div>
                </div>
              </div>

              <div className='mt-2 rounded-lg border border-gray-100 p-2 bg-gray-50'>
                <div className='flex items-center justify-between mb-1'>
                  <Text type='secondary' size='small'>
                    {t('全局代理/VPN样本概览')}
                  </Text>
                  {dashboardLoading && <Spin size='small' />}
                </div>
                <div className='flex flex-wrap gap-1'>
                  {Object.entries(dashboardStats?.vpn_usage_stats || {})
                    .length === 0 ? (
                    <Text size='small' type='tertiary'>
                      {t('暂无全局样本数据')}
                    </Text>
                  ) : (
                    Object.entries(dashboardStats?.vpn_usage_stats || {}).map(
                      ([key, value]) => (
                        <Tag size='small' key={key} color='grey'>
                          {key}: {value}
                        </Tag>
                      ),
                    )
                  )}
                </div>
              </div>
            </Card>

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
                      {selectedProfileInfo?.device_key?.slice(0, 8) || 'N/A'})
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
                  {showTargetDevices ? t('收起') : t('展开设备列表')}
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
                      columns={buildDeviceColumns(true)}
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
                  const assocUserId = safeInt(assoc.user?.id);
                  const assocDetail = assocUserId
                    ? associationDetails[assocUserId]
                    : null;
                  const effectiveAssoc = assocDetail || assoc;
                  const riskTag = getRiskTag(effectiveAssoc.risk_level);
                  const assocCardKey =
                    assoc.user?.id || assoc.device_profile_id || idx;
                  return (
                    <Card
                      key={assocCardKey}
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
                            percent={Math.round(
                              effectiveAssoc.confidence * 100,
                            )}
                            size='small'
                            stroke={
                              getConfidenceColor(effectiveAssoc.confidence) ===
                              'red'
                                ? '#f5222d'
                                : getConfidenceColor(
                                      effectiveAssoc.confidence,
                                    ) === 'orange'
                                  ? '#fa8c16'
                                  : getConfidenceColor(
                                        effectiveAssoc.confidence,
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
                          <Tag
                            color={getTierStyle(effectiveAssoc.tier).color}
                            size='small'
                          >
                            {getTierStyle(effectiveAssoc.tier).label}
                          </Tag>
                          <Tag size='small'>
                            {effectiveAssoc.match_dimensions}/
                            {effectiveAssoc.total_dimensions} {t('维度匹配')}
                          </Tag>
                        </div>
                      </div>

                      {/* Tier / 解释 / 命中维度 */}
                      <div className='mb-2 rounded-lg border border-gray-100 p-2 bg-gray-50'>
                        <div className='flex flex-wrap items-center gap-2 mb-1'>
                          <Text size='small' type='secondary'>
                            {t('判定层级')}:
                          </Text>
                          <Tag
                            size='small'
                            color={getTierStyle(effectiveAssoc.tier).color}
                          >
                            {getTierStyle(effectiveAssoc.tier).label}
                          </Tag>
                        </div>
                        <div className='text-xs text-gray-700 mb-1'>
                          {t('判定说明')}: {effectiveAssoc.explanation || '-'}
                        </div>
                        <div className='flex flex-wrap items-center gap-1'>
                          <Text size='small' type='secondary'>
                            {t('命中维度')}:
                          </Text>
                          {(effectiveAssoc.matched_dimensions || []).length ===
                          0 ? (
                            <Tag size='small' color='grey'>
                              {t('无')}
                            </Tag>
                          ) : (
                            (effectiveAssoc.matched_dimensions || []).map(
                              (dim) => (
                                <Tag key={dim} size='small' color='green'>
                                  {dim}
                                </Tag>
                              ),
                            )
                          )}
                        </div>
                      </div>

                      {/* 命中维度概览 / 信号摘要 */}
                      <div className='mb-2 rounded-lg border border-gray-100 p-2'>
                        <Text strong size='small'>
                          {t('命中维度概览 / 信号摘要')}
                        </Text>
                        <div className='mt-2 grid grid-cols-1 md:grid-cols-2 gap-2'>
                          {getSignalSummaryByCategory(assoc, assocDetail).map(
                            (group) => (
                              <div
                                key={`${assoc.user.id}-${group.category}`}
                                className='rounded-md border border-gray-100 p-2 bg-white'
                              >
                                <div className='flex items-center justify-between mb-1'>
                                  <Text size='small'>
                                    {getCategoryIcon(group.category)}{' '}
                                    {group.label}
                                  </Text>
                                  <Tag
                                    size='small'
                                    color={
                                      group.matchedCount > 0 ? 'green' : 'grey'
                                    }
                                  >
                                    {group.matchedCount}/{group.totalCount}
                                  </Tag>
                                </div>
                                <div className='flex flex-wrap gap-1'>
                                  {group.topSignals.length === 0 ? (
                                    <Text type='tertiary' size='small'>
                                      {t('暂无信号')}
                                    </Text>
                                  ) : (
                                    group.topSignals.map((signal) => (
                                      <Tag
                                        key={`${assoc.user.id}-${group.category}-${signal.dimension}`}
                                        size='small'
                                        color={
                                          signal.highlighted ? 'green' : 'grey'
                                        }
                                      >
                                        {signal.display_name} · w
                                        {(signal.weight || 0).toFixed(2)}
                                      </Tag>
                                    ))
                                  )}
                                </div>
                              </div>
                            ),
                          )}
                        </div>
                      </div>

                      {/* 互斥/时间信号 */}
                      {(() => {
                        const detailSignals = assocDetail?.details || [];
                        const timeSignal = detailSignals.find(
                          (detail) => detail.dimension === 'time_similarity',
                        );
                        const mutualSignal = detailSignals.find(
                          (detail) => detail.dimension === 'mutual_exclusion',
                        );
                        if (!timeSignal && !mutualSignal) return null;
                        return (
                          <div className='mb-2 rounded-lg border border-orange-100 bg-orange-50 p-2'>
                            <Text strong size='small'>
                              {t('时序/互斥信号')}
                            </Text>
                            <div className='mt-1 flex flex-wrap gap-1'>
                              {timeSignal && (
                                <Tag
                                  size='small'
                                  color={
                                    timeSignal.matched ? 'green' : 'yellow'
                                  }
                                >
                                  {t('时间模式相似度')}:{' '}
                                  {(
                                    Number(timeSignal.score || 0) * 100
                                  ).toFixed(0)}
                                  %
                                </Tag>
                              )}
                              {mutualSignal && (
                                <Tag
                                  size='small'
                                  color={
                                    mutualSignal.matched ? 'red' : 'orange'
                                  }
                                >
                                  {t('互斥切换强度')}:{' '}
                                  {(
                                    Number(mutualSignal.score || 0) * 100
                                  ).toFixed(0)}
                                  %
                                </Tag>
                              )}
                            </div>
                            <div className='text-xs text-gray-700 mt-1'>
                              {timeSignal?.matched &&
                                t('活跃时段重叠明显，属于高相关时间特征。')}
                              {timeSignal?.matched && mutualSignal ? ' ' : ''}
                              {mutualSignal?.matched &&
                                t(
                                  '检测到互斥切换模式，存在同设备多账号切换迹象。',
                                )}
                              {!timeSignal?.matched &&
                                !mutualSignal?.matched &&
                                t(
                                  '存在时序相关信号，但强度不足以单独支撑高置信判断。',
                                )}
                            </div>
                          </div>
                        );
                      })()}

                      {/* 共享IP */}
                      {associationDetailLoading[assocUserId] &&
                        !assocDetail && (
                          <div className='mb-2'>
                            <Text size='small' type='tertiary'>
                              {t('正在加载详细信号...')}
                            </Text>
                          </div>
                        )}
                      {assocDetail?.shared_ips &&
                        assocDetail.shared_ips.length > 0 && (
                          <div className='mb-2'>
                            <Text size='small' type='tertiary'>
                              {t('共享IP')}:{' '}
                            </Text>
                            {assocDetail.shared_ips.slice(0, 5).map((ip, i) => (
                              <Tag key={i} size='small' color='grey'>
                                {ip}
                              </Tag>
                            ))}
                            {assocDetail.shared_ips.length > 5 && (
                              <Text size='small' type='tertiary'>
                                ...+{assocDetail.shared_ips.length - 5}
                              </Text>
                            )}
                          </div>
                        )}

                      {/* VPN/代理风险标记 */}
                      {(() => {
                        const hints = getVpnRiskHints(assoc, assocDetail);
                        if (!hints.length) return null;
                        return (
                          <div className='mb-2 rounded-lg border border-red-100 bg-red-50 p-2'>
                            <Text strong size='small'>
                              {t('VPN / 代理风险提示')}
                            </Text>
                            <div className='mt-1 flex flex-wrap gap-1'>
                              {hints.map((hint, index) => (
                                <Tag
                                  key={`${assoc.user.id}-vpn-${index}`}
                                  size='small'
                                  color={
                                    hint.level === 'high'
                                      ? 'red'
                                      : hint.level === 'medium'
                                        ? 'orange'
                                        : 'yellow'
                                  }
                                >
                                  {hint.text}
                                </Tag>
                              ))}
                            </div>
                          </div>
                        );
                      })()}

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
                            ) : (deviceProfiles[assoc.user.id] || []).length ===
                              0 ? (
                              <Text type='tertiary' size='small'>
                                {t('暂无设备档案')}
                              </Text>
                            ) : (
                              <Table
                                size='small'
                                pagination={false}
                                rowKey='id'
                                dataSource={deviceProfiles[assoc.user.id]}
                                columns={buildDeviceColumns(false)}
                              />
                            )}
                          </div>
                        )}
                      </div>

                      {/* 匹配详情 / 时序对比 (可折叠) */}
                      <Collapse
                        onChange={(activeKey) => {
                          const keys = Array.isArray(activeKey)
                            ? activeKey
                            : activeKey
                              ? [activeKey]
                              : [];
                          if (keys.includes('details')) {
                            fetchAssociationProfiles(assoc.user.id);
                            fetchAssociationDetails(assoc.user.id);
                          }
                        }}
                      >
                        <Collapse.Panel
                          header={t('查看匹配详情与时序对比')}
                          itemKey='details'
                        >
                          {assocProfileLoading[assoc.user.id] ? (
                            <Spin size='small' />
                          ) : (
                            <div className='mb-2 rounded-lg border border-gray-100 p-2'>
                              {(!Object.prototype.hasOwnProperty.call(
                                assocTemporalProfiles,
                                assoc.user.id,
                              ) ||
                                !Object.prototype.hasOwnProperty.call(
                                  assocNetworkProfiles,
                                  assoc.user.id,
                                )) && (
                                <Button
                                  size='small'
                                  type='primary'
                                  theme='light'
                                  onClick={() => {
                                    fetchAssociationProfiles(assoc.user.id);
                                    fetchAssociationDetails(assoc.user.id);
                                  }}
                                  className='mb-2'
                                >
                                  {t('加载关联用户画像')}
                                </Button>
                              )}
                              <Text strong size='small'>
                                {t('目标用户 vs 关联用户时序对比')}
                              </Text>
                              <div className='mt-2 grid grid-cols-1 md:grid-cols-2 gap-3'>
                                <div className='rounded-md border border-gray-100 p-2'>
                                  {renderTemporalHeatStrip(
                                    temporalProfile,
                                    `${t('目标用户')} #${safeInt(inputUserId) || inputUserId}`,
                                  )}
                                </div>
                                <div className='rounded-md border border-gray-100 p-2'>
                                  {renderTemporalHeatStrip(
                                    assocTemporalProfiles[assoc.user.id],
                                    `${t('关联用户')} #${assoc.user.id}`,
                                  )}
                                </div>
                              </div>
                              {renderMutualExclusionTimeline(
                                temporalProfile,
                                assocTemporalProfiles[assoc.user.id],
                              )}
                              <div className='mt-2 flex flex-wrap gap-1'>
                                {(() => {
                                  const overlapRatio = getTemporalOverlapRatio(
                                    temporalProfile,
                                    assocTemporalProfiles[assoc.user.id],
                                  );
                                  return (
                                    <Tag size='small' color='cyan'>
                                      {t('时序重叠率')}:{' '}
                                      {overlapRatio === null
                                        ? '-'
                                        : `${Math.round(overlapRatio * 100)}%`}
                                    </Tag>
                                  );
                                })()}
                                <Tag size='small' color='grey'>
                                  {t('关联用户样本')}:{' '}
                                  {assocTemporalProfiles[assoc.user.id]
                                    ?.sample_count ?? '-'}
                                </Tag>
                              </div>
                            </div>
                          )}

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
                                        : cat === 'behavior'
                                          ? t('行为')
                                          : t('环境')}
                                  </span>
                                ),
                              },
                              {
                                title: t('维度'),
                                dataIndex: 'display_name',
                                width: 120,
                                render: (text, record) => {
                                  const highlighted =
                                    record.matched ||
                                    (
                                      effectiveAssoc.matched_dimensions || []
                                    ).includes(record.dimension);
                                  return (
                                    <div className='flex items-center gap-1'>
                                      <Text strong>{text}</Text>
                                      {highlighted && (
                                        <Tag size='small' color='green'>
                                          {t('命中')}
                                        </Tag>
                                      )}
                                    </div>
                                  );
                                },
                              },
                              {
                                title: t('权重'),
                                dataIndex: 'weight',
                                width: 60,
                                render: (w) => (
                                  <Text type='tertiary'>{w?.toFixed(2)}</Text>
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
                            dataSource={
                              assocDetail
                                ? [...(assocDetail.details || [])].sort(
                                    (a, b) => (b.weight || 0) - (a.weight || 0),
                                  )
                                : []
                            }
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
                              'noopener,noreferrer',
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
