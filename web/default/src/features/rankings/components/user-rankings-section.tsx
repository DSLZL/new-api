import { useTranslation } from 'react-i18next'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import type {
  UserRankingMetric,
  UserRankingPeriod,
  UserRankingSelfStat,
  UserRankingVisibility,
} from '../types'
import { RankingPeriodSwitch } from './ranking-period-switch'
import { UserRankingList } from './user-ranking-list'
import { UserRankingTabs } from './user-ranking-tabs'

type UserRankingsSectionProps = {
  metric: UserRankingMetric
  period: UserRankingPeriod
  onMetricChange: (metric: UserRankingMetric) => void
  onPeriodChange: (period: UserRankingPeriod) => void
  visibility: UserRankingVisibility
  updatedAt?: number
  showUserSummary: boolean
  selfStats: UserRankingSelfStat[]
  selfStatsLoading: boolean
  items: Array<{
    rank: number
    user_id: number
    username: string
    display_name: string
    value: number
  }>
}

export function UserRankingsSection(props: UserRankingsSectionProps) {
  const { t } = useTranslation()
  const topTenCount = props.items.slice(0, 10).length

  return (
    <section className='space-y-4'>
      <div className='bg-card rounded-xl border p-4 sm:p-5'>
        <div className='flex flex-wrap items-center justify-between gap-2'>
          <div className='flex flex-wrap items-center gap-2'>
            <Badge variant='outline'>
              {t('Top {{count}}', { count: topTenCount })}
            </Badge>
            {props.updatedAt ? (
              <p className='text-muted-foreground text-xs'>
                {t('Updated at')}: {new Date(props.updatedAt * 1000).toLocaleString()}
              </p>
            ) : null}
          </div>

          <div className='flex flex-wrap items-center gap-2'>
            <Badge variant='outline'>
              {props.metric === 'balance'
                ? t('Balance')
                : props.metric === 'invites'
                  ? t('Invites')
                  : t('Consumption')}
            </Badge>
            {props.metric !== 'balance' && (
              <Badge variant='outline'>
                {props.period === 'daily' ? t('Daily') : t('Total')}
              </Badge>
            )}
          </div>
        </div>

        <div className='mt-4 grid gap-4 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-start'>
          <UserRankingTabs value={props.metric} onChange={props.onMetricChange} />
          {props.metric !== 'balance' && (
            <RankingPeriodSwitch
              value={props.period}
              onChange={props.onPeriodChange}
            />
          )}
        </div>
      </div>

      {props.visibility === 'auth-only' && (
        <Alert className='border-dashed'>
          <AlertTitle>{t('Auth-only')}</AlertTitle>
          <AlertDescription>
            {t('This leaderboard is restricted to logged-in users.')}
          </AlertDescription>
        </Alert>
      )}

      <UserRankingList
        items={props.items}
        showUserSummary={props.showUserSummary}
        selfStats={props.selfStats}
        selfStatsLoading={props.selfStatsLoading}
      />
    </section>
  )
}
