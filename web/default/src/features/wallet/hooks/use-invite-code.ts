import { useCallback, useEffect, useState } from 'react'
import i18next from 'i18next'
import { toast } from 'sonner'
import {
  getInviteCodeDetail,
  getInviteCodeHistory,
  refreshInviteCode,
  updateInviteCodeRules,
} from '../api'
import type {
  AffiliateCodeDetail,
  InviteCodeRefreshPayload,
} from '../types'
import { generateAffiliateLink } from '../lib'

type UpdateInviteCodeRulesInput = {
  maxUses: number
  expireDays: number
}

type UseInviteCodeResult = {
  inviteCode: AffiliateCodeDetail | null
  inviteLink: string
  history: AffiliateCodeDetail[]
  loading: boolean
  saving: boolean
  refreshing: boolean
  historyLoading: boolean
  refreshResult: InviteCodeRefreshPayload | null
  updateRules: (input: UpdateInviteCodeRulesInput) => Promise<boolean>
  refresh: () => Promise<boolean>
  loadHistory: () => Promise<void>
  clearRefreshResult: () => void
  refetch: () => Promise<void>
}

const SECONDS_PER_DAY = 86400

function toExpireAtByDays(days: number): number {
  const normalized = Number.isFinite(days) ? Math.max(1, Math.floor(days)) : 1
  return Math.floor(Date.now() / 1000) + normalized * SECONDS_PER_DAY
}

export function useInviteCode(): UseInviteCodeResult {
  const [inviteCode, setInviteCode] = useState<AffiliateCodeDetail | null>(null)
  const [inviteLink, setInviteLink] = useState('')
  const [history, setHistory] = useState<AffiliateCodeDetail[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [historyLoading, setHistoryLoading] = useState(false)
  const [refreshResult, setRefreshResult] = useState<InviteCodeRefreshPayload | null>(
    null
  )

  const syncInviteState = useCallback((detail: AffiliateCodeDetail | null) => {
    setInviteCode(detail)
    const code = detail?.code ?? ''
    setInviteLink(generateAffiliateLink(code))
    if (code) {
      localStorage.setItem('aff', code)
    }
  }, [])

  const fetchInviteCode = useCallback(async () => {
    try {
      setLoading(true)
      const response = await getInviteCodeDetail()
      if (response.success && response.data) {
        syncInviteState(response.data)
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Failed to fetch invite code detail:', error)
    } finally {
      setLoading(false)
    }
  }, [syncInviteState])

  const loadHistory = useCallback(async () => {
    try {
      setHistoryLoading(true)
      const response = await getInviteCodeHistory()
      if (response.success && response.data) {
        setHistory(response.data)
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Failed to fetch invite code history:', error)
      toast.error(i18next.t('Failed to load invite code history'))
    } finally {
      setHistoryLoading(false)
    }
  }, [])

  const updateRules = useCallback(
    async (input: UpdateInviteCodeRulesInput) => {
      try {
        setSaving(true)
        const response = await updateInviteCodeRules({
          max_uses: Math.max(1, Math.floor(input.maxUses)),
          expires_at: toExpireAtByDays(input.expireDays),
        })
        if (response.success && response.data) {
          syncInviteState(response.data)
          toast.success(i18next.t('Invite code settings saved'))
          return true
        }
        toast.error(response.message || i18next.t('Failed to save invite code settings'))
        return false
      } catch (_error) {
        toast.error(i18next.t('Failed to save invite code settings'))
        return false
      } finally {
        setSaving(false)
      }
    },
    [syncInviteState]
  )

  const refresh = useCallback(async () => {
    try {
      setRefreshing(true)
      const response = await refreshInviteCode()
      if (response.success && response.data?.current) {
        syncInviteState(response.data.current)
        setRefreshResult(response.data)
        toast.success(i18next.t('Invite code refreshed'))
        return true
      }
      toast.error(response.message || i18next.t('Failed to refresh invite code'))
      return false
    } catch (_error) {
      toast.error(i18next.t('Failed to refresh invite code'))
      return false
    } finally {
      setRefreshing(false)
    }
  }, [syncInviteState])

  const clearRefreshResult = useCallback(() => {
    setRefreshResult(null)
  }, [])

  useEffect(() => {
    fetchInviteCode()
  }, [fetchInviteCode])

  return {
    inviteCode,
    inviteLink,
    history,
    loading,
    saving,
    refreshing,
    historyLoading,
    refreshResult,
    updateRules,
    refresh,
    loadHistory,
    clearRefreshResult,
    refetch: fetchInviteCode,
  }
}
