import { api } from '@/lib/api'
import type {
  RankingPeriod,
  RankingsSnapshot,
  UserRankingMetric,
  UserRankingPeriod,
  UserRankingsSnapshot,
} from './types'

type RankingsResponse = {
  success: boolean
  message?: string
  data: RankingsSnapshot
}

type UserRankingsResponse = {
  success: boolean
  message?: string
  code?: string
  data: UserRankingsSnapshot
}

export async function getRankings(
  period: RankingPeriod
): Promise<RankingsResponse> {
  const res = await api.get('/api/rankings', { params: { period } })
  return res.data
}

export async function getUserRankings(
  metric: UserRankingMetric,
  period: UserRankingPeriod,
  date?: string
): Promise<UserRankingsResponse> {
  const res = await api.get('/api/rankings', {
    params: { scope: 'users', metric, period, date },
  })
  return res.data
}
