import axios from 'axios'
import { useQuery } from '@tanstack/react-query'
import { getAuthErrorCode } from '@/lib/api'
import { getUserRankings } from '../api'
import type {
  UserRankingMetric,
  UserRankingPeriod,
  UserRankingSelfStat,
} from '../types'

const TEN_MINUTES_MS = 10 * 60 * 1000

function getMsUntilNextTenMinuteBoundary() {
  const now = new Date()
  const next = new Date(now)
  next.setSeconds(0, 0)
  next.setMinutes(Math.floor(now.getMinutes() / 10) * 10 + 10)
  return next.getTime() - now.getTime()
}

export function useUserRankings(
  metric: UserRankingMetric,
  period: UserRankingPeriod
) {
  return useQuery({
    queryKey: ['rankings', 'users', metric, period],
    queryFn: () => getUserRankings(metric, period),
    staleTime: 5 * 60 * 1000,
    refetchInterval: () => {
      const ms = getMsUntilNextTenMinuteBoundary()
      return ms > 0 ? ms : TEN_MINUTES_MS
    },
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: (failureCount, error) => {
      if (
        axios.isAxiosError(error) &&
        error.response?.status === 401 &&
        getAuthErrorCode(error.response?.data) === 'AUTH_NOT_LOGGED_IN'
      ) {
        return false
      }
      return failureCount < 2
    },
  })
}

function findSelfStat(
  items:
    | Array<{
        rank: number
        user_id: number
        value: number
      }>
    | undefined,
  userId: number
): { value: number | null; rank: number | null } {
  if (!Array.isArray(items)) {
    return { value: null, rank: null }
  }
  const matched = items.find((item) => item.user_id === userId)
  if (!matched) {
    return { value: null, rank: null }
  }
  return { value: matched.value, rank: matched.rank }
}

export function useUserRankingSelfStats(userId?: number | null) {
  const enabled = Boolean(userId)

  const balanceTotalQuery = useQuery({
    queryKey: ['rankings', 'users', 'self', 'balance', 'total', userId],
    queryFn: () => getUserRankings('balance', 'total'),
    enabled,
    staleTime: 5 * 60 * 1000,
    refetchInterval: () => {
      const ms = getMsUntilNextTenMinuteBoundary()
      return ms > 0 ? ms : TEN_MINUTES_MS
    },
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: (failureCount, error) => {
      if (
        axios.isAxiosError(error) &&
        error.response?.status === 401 &&
        getAuthErrorCode(error.response?.data) === 'AUTH_NOT_LOGGED_IN'
      ) {
        return false
      }
      return failureCount < 2
    },
  })

  const invitesDailyQuery = useQuery({
    queryKey: ['rankings', 'users', 'self', 'invites', 'daily', userId],
    queryFn: () => getUserRankings('invites', 'daily'),
    enabled,
    staleTime: 5 * 60 * 1000,
    refetchInterval: () => {
      const ms = getMsUntilNextTenMinuteBoundary()
      return ms > 0 ? ms : TEN_MINUTES_MS
    },
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: (failureCount, error) => {
      if (
        axios.isAxiosError(error) &&
        error.response?.status === 401 &&
        getAuthErrorCode(error.response?.data) === 'AUTH_NOT_LOGGED_IN'
      ) {
        return false
      }
      return failureCount < 2
    },
  })

  const invitesTotalQuery = useQuery({
    queryKey: ['rankings', 'users', 'self', 'invites', 'total', userId],
    queryFn: () => getUserRankings('invites', 'total'),
    enabled,
    staleTime: 5 * 60 * 1000,
    refetchInterval: () => {
      const ms = getMsUntilNextTenMinuteBoundary()
      return ms > 0 ? ms : TEN_MINUTES_MS
    },
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: (failureCount, error) => {
      if (
        axios.isAxiosError(error) &&
        error.response?.status === 401 &&
        getAuthErrorCode(error.response?.data) === 'AUTH_NOT_LOGGED_IN'
      ) {
        return false
      }
      return failureCount < 2
    },
  })

  const consumptionDailyQuery = useQuery({
    queryKey: ['rankings', 'users', 'self', 'consumption', 'daily', userId],
    queryFn: () => getUserRankings('consumption', 'daily'),
    enabled,
    staleTime: 5 * 60 * 1000,
    refetchInterval: () => {
      const ms = getMsUntilNextTenMinuteBoundary()
      return ms > 0 ? ms : TEN_MINUTES_MS
    },
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: (failureCount, error) => {
      if (
        axios.isAxiosError(error) &&
        error.response?.status === 401 &&
        getAuthErrorCode(error.response?.data) === 'AUTH_NOT_LOGGED_IN'
      ) {
        return false
      }
      return failureCount < 2
    },
  })

  const consumptionTotalQuery = useQuery({
    queryKey: ['rankings', 'users', 'self', 'consumption', 'total', userId],
    queryFn: () => getUserRankings('consumption', 'total'),
    enabled,
    staleTime: 5 * 60 * 1000,
    refetchInterval: () => {
      const ms = getMsUntilNextTenMinuteBoundary()
      return ms > 0 ? ms : TEN_MINUTES_MS
    },
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: (failureCount, error) => {
      if (
        axios.isAxiosError(error) &&
        error.response?.status === 401 &&
        getAuthErrorCode(error.response?.data) === 'AUTH_NOT_LOGGED_IN'
      ) {
        return false
      }
      return failureCount < 2
    },
  })

  const uid = userId ?? 0
  const stats: UserRankingSelfStat[] = [
    {
      metric: 'balance',
      period: 'total',
      ...findSelfStat(balanceTotalQuery.data?.data?.items, uid),
    },
    {
      metric: 'consumption',
      period: 'daily',
      ...findSelfStat(consumptionDailyQuery.data?.data?.items, uid),
    },
    {
      metric: 'consumption',
      period: 'total',
      ...findSelfStat(consumptionTotalQuery.data?.data?.items, uid),
    },
    {
      metric: 'invites',
      period: 'daily',
      ...findSelfStat(invitesDailyQuery.data?.data?.items, uid),
    },
    {
      metric: 'invites',
      period: 'total',
      ...findSelfStat(invitesTotalQuery.data?.data?.items, uid),
    },
  ]

  const isLoading =
    enabled &&
    [
      balanceTotalQuery,
      invitesDailyQuery,
      invitesTotalQuery,
      consumptionDailyQuery,
      consumptionTotalQuery,
    ].some((query) => query.isLoading)

  return { stats, isLoading }
}
