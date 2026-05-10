import axios from 'axios'
import { useNavigate, useSearch } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'
import { getAuthErrorCode } from '@/lib/api'
import { Skeleton } from '@/components/ui/skeleton'
import { PublicLayout } from '@/components/layout'
import { PageTransition } from '@/components/page-transition'
import { useAuthStore } from '@/stores/auth-store'
import { UserRankingsSection } from './components'
import {
  useUserRankingSelfStats,
  useUserRankings,
} from './hooks/use-user-rankings'
import type {
  UserRankingMetric,
  UserRankingPeriod,
} from './types'

const VALID_METRICS: UserRankingMetric[] = ['balance', 'invites', 'consumption']
const VALID_PERIODS: UserRankingPeriod[] = ['daily', 'total']

export function Rankings() {
  const { t } = useTranslation()
  const search = useSearch({ from: '/rankings/' })
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.auth.user)

  const metric: UserRankingMetric = VALID_METRICS.includes(
    search.metric as UserRankingMetric
  )
    ? (search.metric as UserRankingMetric)
    : 'balance'

  const period: UserRankingPeriod =
    metric === 'balance'
      ? 'total'
      : VALID_PERIODS.includes(search.period as UserRankingPeriod)
        ? (search.period as UserRankingPeriod)
        : 'total'

  const rankingsQuery = useUserRankings(metric, period)
  const snapshot = rankingsQuery.data?.data
  const selfStatsQuery = useUserRankingSelfStats(user?.id)

  const handleMetricChange = (next: UserRankingMetric) => {
    const nextPeriod = next === 'balance' ? 'total' : period
    navigate({
      to: '/rankings',
      search: (prev) => ({ ...prev, metric: next, period: nextPeriod }),
    })
  }

  const handlePeriodChange = (next: UserRankingPeriod) => {
    navigate({
      to: '/rankings',
      search: (prev) => ({ ...prev, period: next }),
    })
  }

  const rankingErrorMessage = (() => {
    if (!rankingsQuery.error) return t('Unable to load user rankings')
    if (axios.isAxiosError(rankingsQuery.error)) {
      const status = rankingsQuery.error.response?.status
      const code = getAuthErrorCode(rankingsQuery.error.response?.data)
      if (status === 401 && code === 'AUTH_NOT_LOGGED_IN') {
        return t('This leaderboard is restricted to logged-in users.')
      }
      return (
        rankingsQuery.error.response?.data?.message ??
        rankingsQuery.error.message
      )
    }
    if (rankingsQuery.error instanceof Error) {
      return rankingsQuery.error.message
    }
    return t('Unable to load user rankings')
  })()

  const showAuthAction =
    axios.isAxiosError(rankingsQuery.error) &&
    rankingsQuery.error.response?.status === 401 &&
    getAuthErrorCode(rankingsQuery.error.response?.data) ===
      'AUTH_NOT_LOGGED_IN'
  const showUserSummary = Boolean(user)
  const selfStats = selfStatsQuery.stats

  return (
    <PublicLayout showMainContainer={false}>
      <div className='relative'>
        <div
          aria-hidden
          className='pointer-events-none absolute inset-x-0 top-0 h-[600px] opacity-20 dark:opacity-[0.10]'
          style={{
            background: [
              'radial-gradient(ellipse 60% 50% at 20% 20%, oklch(0.72 0.18 250 / 80%) 0%, transparent 70%)',
              'radial-gradient(ellipse 50% 40% at 80% 15%, oklch(0.65 0.15 200 / 60%) 0%, transparent 70%)',
              'radial-gradient(ellipse 40% 35% at 50% 70%, oklch(0.70 0.12 280 / 40%) 0%, transparent 70%)',
            ].join(', '),
            maskImage:
              'linear-gradient(to bottom, black 40%, transparent 100%)',
            WebkitMaskImage:
              'linear-gradient(to bottom, black 40%, transparent 100%)',
          }}
        />
        <PageTransition className='relative mx-auto w-full max-w-[1080px] space-y-8 px-3 pt-16 pb-10 sm:px-6 sm:pt-20 sm:pb-12 xl:px-8'>
          <section className='space-y-2'>
            <p className='text-muted-foreground text-xs font-medium tracking-widest uppercase'>
              {t('Leaderboards')}
            </p>
            <h1 className='text-[clamp(1.75rem,4vw,2.5rem)] leading-[1.15] font-bold tracking-tight'>
              {t('User Rankings')}
            </h1>
            <p className='text-muted-foreground/80 max-w-2xl text-sm'>
              {t(
                'Track top users by balance, invites, and quota consumption in real time.'
              )}
            </p>
          </section>

          {rankingsQuery.isLoading ? (
            <RankingsLoading />
          ) : !snapshot ? (
            <RankingsError
              message={rankingErrorMessage}
              showAuthAction={showAuthAction}
            />
          ) : (
            <UserRankingsSection
              metric={metric}
              period={period}
              onMetricChange={handleMetricChange}
              onPeriodChange={handlePeriodChange}
              visibility={snapshot.visibility}
              updatedAt={snapshot.updated_at}
              showUserSummary={showUserSummary}
              items={snapshot.items}
              selfStats={selfStats}
              selfStatsLoading={selfStatsQuery.isLoading}
            />
          )}
        </PageTransition>
      </div>
    </PublicLayout>
  )
}

function RankingsLoading() {
  return (
    <div className='space-y-6'>
      <Skeleton className='h-[120px] w-full rounded-xl' />
      <Skeleton className='h-[64px] w-full rounded-xl' />
      <Skeleton className='h-[420px] w-full rounded-xl' />
    </div>
  )
}

function RankingsError(props: { message: string; showAuthAction: boolean }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  return (
    <div className='bg-card rounded-xl border border-dashed px-6 py-12 text-center'>
      <h2 className='text-foreground text-base font-semibold'>
        {t('Unable to load user rankings')}
      </h2>
      <p className='text-muted-foreground mx-auto mt-2 max-w-md text-sm'>
        {props.message}
      </p>
      {props.showAuthAction && (
        <button
          type='button'
          className='bg-primary text-primary-foreground mt-4 inline-flex h-9 items-center rounded-md px-4 text-sm font-medium'
          onClick={() =>
            navigate({ to: '/sign-in', search: { redirect: '/rankings' } })
          }
        >
          {t('Sign In')}
        </button>
      )}
    </div>
  )
}
