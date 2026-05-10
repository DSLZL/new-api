import { useTranslation } from 'react-i18next'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { UserRankingPeriod } from '../types'

type RankingPeriodSwitchProps = {
  value: UserRankingPeriod
  onChange: (value: UserRankingPeriod) => void
}

const PERIODS: Array<{ id: UserRankingPeriod; labelKey: string }> = [
  { id: 'daily', labelKey: 'Daily' },
  { id: 'total', labelKey: 'Total' },
]

export function RankingPeriodSwitch(props: RankingPeriodSwitchProps) {
  const { t } = useTranslation()

  return (
    <Tabs value={props.value} onValueChange={props.onChange}>
      <TabsList className='bg-muted/40 h-auto max-w-full flex-wrap justify-start gap-1 rounded-xl p-1'>
        {PERIODS.map((period) => (
          <TabsTrigger
            key={period.id}
            value={period.id}
            className='px-3 py-1.5 text-sm data-[state=active]:shadow-sm'
          >
            {t(period.labelKey)}
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  )
}
