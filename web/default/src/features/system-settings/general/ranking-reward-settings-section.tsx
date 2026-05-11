import { useEffect, useMemo, useState } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import { z } from 'zod'
import { useForm, type Resolver } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { SettingsSection } from '../components/settings-section'
import { useUpdateOption } from '../hooks/use-update-option'

const schema = z.object({
  enabled: z.boolean(),
})

type Values = z.infer<typeof schema>

type RuleInputRow = {
  rank: string
  quota: string
}

type LeaderboardId =
  | 'balanceDaily'
  | 'balanceTotal'
  | 'invitesDaily'
  | 'invitesTotal'
  | 'consumptionDaily'
  | 'consumptionTotal'

type RulesForm = Record<LeaderboardId, RuleInputRow[]>

type ValidationErrors = Record<string, string>

const LEADERBOARDS: Array<{
  id: LeaderboardId
  optionKey: string
  titleKey: string
}> = [
  {
    id: 'balanceDaily',
    optionKey: 'balance.daily',
    titleKey: 'Daily Balance Leaderboard',
  },
  {
    id: 'balanceTotal',
    optionKey: 'balance.total',
    titleKey: 'Total Balance Leaderboard',
  },
  {
    id: 'invitesDaily',
    optionKey: 'invites.daily',
    titleKey: 'Daily Invites Leaderboard',
  },
  {
    id: 'invitesTotal',
    optionKey: 'invites.total',
    titleKey: 'Total Invites Leaderboard',
  },
  {
    id: 'consumptionDaily',
    optionKey: 'consumption.daily',
    titleKey: 'Daily Consumption Leaderboard',
  },
  {
    id: 'consumptionTotal',
    optionKey: 'consumption.total',
    titleKey: 'Total Consumption Leaderboard',
  },
]

function emptyRulesForm(): RulesForm {
  return {
    balanceDaily: [],
    balanceTotal: [],
    invitesDaily: [],
    invitesTotal: [],
    consumptionDaily: [],
    consumptionTotal: [],
  }
}

function parseRulesForm(raw: string): RulesForm {
  const parsedRules = emptyRulesForm()
  const trimmed = raw.trim()
  if (!trimmed) {
    return parsedRules
  }

  try {
    const parsed = JSON.parse(trimmed)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return parsedRules
    }

    for (const leaderboard of LEADERBOARDS) {
      const rows = (parsed as Record<string, unknown>)[leaderboard.optionKey]
      if (!Array.isArray(rows)) {
        continue
      }

      const validRows: RuleInputRow[] = []
      for (const row of rows) {
        if (!row || typeof row !== 'object' || Array.isArray(row)) {
          continue
        }
        const rank = (row as Record<string, unknown>).rank
        const quota = (row as Record<string, unknown>).quota
        validRows.push({
          rank:
            typeof rank === 'number' || typeof rank === 'string'
              ? String(rank)
              : '',
          quota:
            typeof quota === 'number' || typeof quota === 'string'
              ? String(quota)
              : '',
        })
      }
      parsedRules[leaderboard.id] = validRows
    }
  } catch {
    return parsedRules
  }

  return parsedRules
}

function serializeRulesForm(rules: RulesForm): string {
  const payload: Record<string, Array<{ rank: number; quota: number }>> = {}

  for (const leaderboard of LEADERBOARDS) {
    const rows = rules[leaderboard.id]
      .map((row) => {
        const rank = Number(row.rank)
        const quota = Number(row.quota)
        if (
          !Number.isInteger(rank) ||
          rank <= 0 ||
          !Number.isInteger(quota) ||
          quota < 0
        ) {
          return null
        }
        return { rank, quota }
      })
      .filter((row): row is { rank: number; quota: number } => row !== null)
      .sort((a, b) => a.rank - b.rank)

    if (rows.length > 0) {
      payload[leaderboard.optionKey] = rows
    }
  }

  return JSON.stringify(payload)
}

function validateRulesForm(rules: RulesForm): ValidationErrors {
  const errors: ValidationErrors = {}

  for (const leaderboard of LEADERBOARDS) {
    const seenRanks = new Set<number>()
    rules[leaderboard.id].forEach((row, index) => {
      const rank = Number(row.rank)
      const quota = Number(row.quota)
      const rankErrorKey = `${leaderboard.id}:${index}:rank`
      const quotaErrorKey = `${leaderboard.id}:${index}:quota`

      if (!Number.isInteger(rank) || rank <= 0) {
        errors[rankErrorKey] = 'Rank must be a positive integer'
      } else if (seenRanks.has(rank)) {
        errors[rankErrorKey] = 'Duplicate rank in the same leaderboard'
      } else {
        seenRanks.add(rank)
      }

      if (!Number.isInteger(quota) || quota < 0) {
        errors[quotaErrorKey] = 'Quota must be a non-negative integer'
      }
    })
  }

  return errors
}

export function RankingRewardSettingsSection({
  defaultValues,
}: {
  defaultValues: {
    enabled: boolean
    rules: string
  }
}) {
  const { t } = useTranslation()
  const updateOption = useUpdateOption()

  const form = useForm<Values>({
    resolver: zodResolver(schema) as unknown as Resolver<Values>,
    defaultValues: {
      enabled: defaultValues.enabled,
    },
  })

  const [rules, setRules] = useState<RulesForm>(() =>
    parseRulesForm(defaultValues.rules)
  )
  const [savedEnabled, setSavedEnabled] = useState(defaultValues.enabled)
  const [savedRulesJson, setSavedRulesJson] = useState(() =>
    serializeRulesForm(parseRulesForm(defaultValues.rules))
  )
  const [validationErrors, setValidationErrors] = useState<ValidationErrors>({})

  useEffect(() => {
    const parsedRules = parseRulesForm(defaultValues.rules)
    const serializedRules = serializeRulesForm(parsedRules)
    setRules(parsedRules)
    setSavedEnabled(defaultValues.enabled)
    setSavedRulesJson(serializedRules)
    setValidationErrors({})
    form.reset({ enabled: defaultValues.enabled })
  }, [defaultValues.enabled, defaultValues.rules, form])

  const enabled = form.watch('enabled')
  const currentRulesJson = useMemo(() => serializeRulesForm(rules), [rules])
  const hasChanges =
    enabled !== savedEnabled || currentRulesJson !== savedRulesJson

  const isBusy = updateOption.isPending || form.formState.isSubmitting

  function updateRuleValue(
    leaderboardId: LeaderboardId,
    index: number,
    key: keyof RuleInputRow,
    value: string
  ) {
    setRules((prev) => {
      const next = { ...prev }
      const rows = [...next[leaderboardId]]
      rows[index] = { ...rows[index], [key]: value }
      next[leaderboardId] = rows
      return next
    })
    setValidationErrors({})
  }

  function addRule(leaderboardId: LeaderboardId) {
    setRules((prev) => {
      const next = { ...prev }
      next[leaderboardId] = [
        ...next[leaderboardId],
        { rank: String(next[leaderboardId].length + 1), quota: '0' },
      ]
      return next
    })
    setValidationErrors({})
  }

  function removeRule(leaderboardId: LeaderboardId, index: number) {
    setRules((prev) => {
      const next = { ...prev }
      next[leaderboardId] = next[leaderboardId].filter((_, i) => i !== index)
      return next
    })
    setValidationErrors({})
  }

  async function onSubmit(values: Values) {
    const errors = validateRulesForm(rules)
    if (Object.keys(errors).length > 0) {
      setValidationErrors(errors)
      toast.error(t('Please fix ranking reward rules before saving'))
      return
    }

    const nextRulesJson = serializeRulesForm(rules)
    const updates: Array<{ key: string; value: string }> = []

    if (values.enabled !== savedEnabled) {
      updates.push({
        key: 'ranking_reward_setting.enabled',
        value: String(values.enabled),
      })
    }

    if (nextRulesJson !== savedRulesJson) {
      updates.push({
        key: 'ranking_reward_setting.rules',
        value: nextRulesJson,
      })
    }

    if (updates.length === 0) {
      toast.info(t('No changes to save'))
      return
    }

    for (const update of updates) {
      await updateOption.mutateAsync(update)
    }

    setSavedEnabled(values.enabled)
    setSavedRulesJson(nextRulesJson)
    setValidationErrors({})
    form.reset({ enabled: values.enabled })
  }

  return (
    <SettingsSection
      title={t('Ranking Reward Settings')}
      description={t(
        'Configure next-day quota rewards for top leaderboard users'
      )}
    >
      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(onSubmit)}
          autoComplete='off'
          className='space-y-6'
        >
          <FormField
            control={form.control}
            name='enabled'
            render={({ field }) => (
              <FormItem className='flex flex-row items-center justify-between rounded-lg border p-4'>
                <div className='space-y-0.5'>
                  <FormLabel className='text-base'>
                    {t('Enable ranking rewards')}
                  </FormLabel>
                  <FormDescription>
                    {t(
                      'When enabled, rewards are settled the next day based on the previous Beijing day snapshots.'
                    )}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                    disabled={isBusy}
                  />
                </FormControl>
              </FormItem>
            )}
          />

          {enabled && (
            <div className='space-y-4'>
              {LEADERBOARDS.map((leaderboard) => (
                <div
                  key={leaderboard.id}
                  className='space-y-3 rounded-lg border p-4'
                >
                  <div className='space-y-1'>
                    <p className='text-sm font-medium'>
                      {t(leaderboard.titleKey)}
                    </p>
                  </div>

                  <div className='space-y-3'>
                    {rules[leaderboard.id].map((row, index) => {
                      const rankErrorKey = `${leaderboard.id}:${index}:rank`
                      const quotaErrorKey = `${leaderboard.id}:${index}:quota`
                      const rankError = validationErrors[rankErrorKey]
                      const quotaError = validationErrors[quotaErrorKey]

                      return (
                        <div
                          key={`${leaderboard.id}-${index}`}
                          className='grid grid-cols-1 gap-3 sm:grid-cols-[1fr_1fr_auto]'
                        >
                          <div className='space-y-1'>
                            <FormLabel>{t('Rank (positive integer)')}</FormLabel>
                            <Input
                              type='number'
                              min={1}
                              step={1}
                              value={row.rank}
                              onChange={(event) =>
                                updateRuleValue(
                                  leaderboard.id,
                                  index,
                                  'rank',
                                  event.target.value
                                )
                              }
                              disabled={isBusy}
                            />
                            {rankError && (
                              <p className='text-destructive text-sm'>
                                {t(rankError)}
                              </p>
                            )}
                          </div>

                          <div className='space-y-1'>
                            <FormLabel>{t('Quota reward (integer >= 0)')}</FormLabel>
                            <Input
                              type='number'
                              min={0}
                              step={1}
                              value={row.quota}
                              onChange={(event) =>
                                updateRuleValue(
                                  leaderboard.id,
                                  index,
                                  'quota',
                                  event.target.value
                                )
                              }
                              disabled={isBusy}
                            />
                            {quotaError && (
                              <p className='text-destructive text-sm'>
                                {t(quotaError)}
                              </p>
                            )}
                          </div>

                          <div className='flex items-end'>
                            <Button
                              type='button'
                              variant='outline'
                              size='icon'
                              onClick={() => removeRule(leaderboard.id, index)}
                              disabled={isBusy}
                              aria-label={t('Remove reward rule')}
                            >
                              <Trash2 className='h-4 w-4' />
                            </Button>
                          </div>
                        </div>
                      )
                    })}
                  </div>

                  <Button
                    type='button'
                    variant='outline'
                    size='sm'
                    onClick={() => addRule(leaderboard.id)}
                    disabled={isBusy}
                  >
                    <Plus className='mr-2 h-4 w-4' />
                    {t('Add reward rule')}
                  </Button>
                </div>
              ))}
            </div>
          )}

          <Button type='submit' disabled={!hasChanges || isBusy}>
            {isBusy ? t('Saving...') : t('Save ranking reward settings')}
          </Button>
        </form>
      </Form>
    </SettingsSection>
  )
}
