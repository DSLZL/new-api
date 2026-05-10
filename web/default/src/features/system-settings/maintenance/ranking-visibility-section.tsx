import { useEffect } from 'react'
import * as z from 'zod'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Switch } from '@/components/ui/switch'
import { SettingsSection } from '../components/settings-section'
import { useUpdateOption } from '../hooks/use-update-option'

const rankingVisibilitySchema = z.object({
  authOnly: z.boolean(),
})

type RankingVisibilityFormValues = z.infer<typeof rankingVisibilitySchema>

type RankingVisibilitySectionProps = {
  value: string
}

const normalizeVisibility = (value: string): 'public' | 'auth-only' => {
  return value === 'auth-only' ? 'auth-only' : 'public'
}

export function RankingVisibilitySection({
  value,
}: RankingVisibilitySectionProps) {
  const { t } = useTranslation()
  const updateOption = useUpdateOption()
  const normalizedValue = normalizeVisibility(value)
  const isAuthOnly = normalizedValue === 'auth-only'

  const form = useForm<RankingVisibilityFormValues>({
    resolver: zodResolver(rankingVisibilitySchema),
    defaultValues: {
      authOnly: isAuthOnly,
    },
  })

  useEffect(() => {
    form.reset({ authOnly: isAuthOnly })
  }, [form, isAuthOnly])

  const onSubmit = async (values: RankingVisibilityFormValues) => {
    if (values.authOnly === isAuthOnly) {
      return
    }
    await updateOption.mutateAsync({
      key: 'ranking_setting.user_visibility',
      value: values.authOnly ? 'auth-only' : 'public',
    })
  }

  return (
    <SettingsSection
      title={t('Leaderboard visibility')}
      description={t('Choose who can access the user rankings page.')}
    >
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className='space-y-6'>
          <FormField
            control={form.control}
            name='authOnly'
            render={({ field }) => (
              <FormItem className='flex flex-row items-start justify-between rounded-lg border p-4'>
                <div className='space-y-0.5 pe-4'>
                  <FormLabel className='text-base'>{t('Auth-only')}</FormLabel>
                  <FormDescription>
                    {field.value
                      ? t('Only logged-in users can view user rankings.')
                      : t('Anyone can view user rankings without login.')}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <Button type='submit' disabled={updateOption.isPending}>
            {updateOption.isPending
              ? t('Saving...')
              : t('Save leaderboard visibility')}
          </Button>
        </form>
      </Form>
    </SettingsSection>
  )
}
