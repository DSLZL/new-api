import { useTranslation } from 'react-i18next'
import { formatNumber, formatQuota } from '@/lib/format'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import type { UserRankingItem, UserRankingSelfStat } from '../types'

type UserRankingListProps = {
  items: UserRankingItem[]
  showUserSummary: boolean
  selfStats: UserRankingSelfStat[]
  selfStatsLoading: boolean
}

export function UserRankingList(props: UserRankingListProps) {
  const { t } = useTranslation()
  const topTenItems = props.items.slice(0, 10)

  if (topTenItems.length === 0) {
    return (
      <div className='rounded-xl border border-dashed px-6 py-10 text-center'>
        <p className='text-foreground text-sm font-medium'>
          {t('No ranking data yet')}
        </p>
        <p className='text-muted-foreground mt-2 text-sm'>
          {t('No users match this ranking yet.')}
        </p>
      </div>
    )
  }

  const containerClass = props.showUserSummary
    ? 'grid gap-4 xl:grid-cols-[minmax(0,1fr)_280px]'
    : 'grid gap-4'

  return (
    <div className={containerClass}>
      <div className='bg-card overflow-hidden rounded-xl border'>
        <Table>
          <TableHeader className='bg-muted/45'>
            <TableRow className='hover:bg-muted/45'>
              <TableHead className='w-[84px] px-4 py-3 text-xs tracking-wide uppercase'>
                {t('Rank')}
              </TableHead>
              <TableHead className='px-3 py-3 text-xs tracking-wide uppercase'>
                {t('User')}
              </TableHead>
              <TableHead className='px-4 py-3 text-right text-xs tracking-wide uppercase'>
                {t('Value')}
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {topTenItems.map((item) => (
              <TableRow key={item.user_id}>
                <TableCell className='px-4 py-3'>
                  <RankBadge rank={item.rank} />
                </TableCell>
                <TableCell className='px-3 py-3'>
                  <div className='min-w-0'>
                    <p className='truncate font-medium'>
                      {item.display_name || item.username}
                    </p>
                    <p className='text-muted-foreground truncate text-xs'>
                      @{item.username}
                    </p>
                  </div>
                </TableCell>
                <TableCell className='px-4 py-3 text-right'>
                  <span className='text-foreground tabular-nums font-semibold'>
                    {formatNumber(item.value)}
                  </span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {props.showUserSummary && (
        <aside className='bg-card rounded-xl border p-4'>
          <p className='text-muted-foreground text-xs font-semibold tracking-wide uppercase'>
            {t('My ranking snapshot')}
          </p>
          {props.selfStatsLoading ? (
            <div className='mt-3 rounded-lg border border-dashed px-3 py-4 text-sm text-muted-foreground'>
              ...
            </div>
          ) : (
            <div className='mt-3 space-y-2'>
              {props.selfStats.map((stat) => (
                <div
                  key={`${stat.metric}-${stat.period}`}
                  className='bg-muted/35 flex items-center justify-between rounded-lg border px-3 py-2'
                >
                  <div className='min-w-0'>
                    <p className='truncate text-sm font-medium'>
                      {stat.metric === 'balance'
                        ? `${t('Balance')} (${t('Total')})`
                        : stat.metric === 'consumption'
                          ? `${t('Consumption')} (${stat.period === 'daily' ? t('Daily') : t('Total')})`
                          : `${t('Invites')} (${stat.period === 'daily' ? t('Daily') : t('Total')})`}
                    </p>
                    <p className='text-muted-foreground truncate text-xs'>
                      {t('Current rank')}:{' '}
                      {stat.rank == null ? t('Unranked') : `#${stat.rank}`}
                    </p>
                  </div>
                  <span className='tabular-nums text-sm font-semibold'>
                    {stat.value == null
                      ? t('No data')
                      : stat.metric === 'invites'
                        ? formatNumber(stat.value)
                        : formatQuota(stat.value)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </aside>
      )}
    </div>
  )
}

function RankBadge(props: { rank: number }) {
  if (props.rank === 1) {
    return <Badge className='bg-amber-500/15 text-amber-700'>#1</Badge>
  }
  if (props.rank === 2) {
    return <Badge className='bg-slate-500/15 text-slate-700'>#2</Badge>
  }
  if (props.rank === 3) {
    return <Badge className='bg-orange-500/15 text-orange-700'>#3</Badge>
  }
  return <Badge variant='outline'>#{props.rank}</Badge>
}
