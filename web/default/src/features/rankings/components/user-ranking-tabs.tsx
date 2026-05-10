import { useTranslation } from 'react-i18next'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { UserRankingMetric } from '../types'

type UserRankingTabsProps = {
  value: UserRankingMetric
  onChange: (value: UserRankingMetric) => void
}

const METRICS: Array<{ id: UserRankingMetric; labelKey: string }> = [
  { id: 'balance', labelKey: 'Balance' },
  { id: 'invites', labelKey: 'Invites' },
  { id: 'consumption', labelKey: 'Consumption' },
]

export function UserRankingTabs(props: UserRankingTabsProps) {
  const { t } = useTranslation()

  return (
    <Tabs value={props.value} onValueChange={props.onChange}>
      <TabsList className='bg-muted/40 h-auto max-w-full flex-wrap justify-start gap-1 rounded-xl p-1'>
        {METRICS.map((metric) => (
          <TabsTrigger
            key={metric.id}
            value={metric.id}
            className='px-3 py-1.5 text-sm data-[state=active]:shadow-sm'
          >
            {t(metric.labelKey)}
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  )
}
