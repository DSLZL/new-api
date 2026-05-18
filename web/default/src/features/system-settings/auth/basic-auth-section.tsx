import { useMemo } from 'react'
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
import { Textarea } from '@/components/ui/textarea'
import { Input } from '@/components/ui/input'
import { SettingsSection } from '../components/settings-section'
import { useResetForm } from '../hooks/use-reset-form'
import { useUpdateOption } from '../hooks/use-update-option'

const basicAuthSchema = z.object({
  PasswordLoginEnabled: z.boolean(),
  PasswordRegisterEnabled: z.boolean(),
  InviteOnlyRegistrationEnabled: z.boolean(),
  EmailVerificationEnabled: z.boolean(),
  RegisterEnabled: z.boolean(),
  EmailDomainRestrictionEnabled: z.boolean(),
  EmailAliasRestrictionEnabled: z.boolean(),
  EmailDomainWhitelist: z.string(),
  invite_code_max_uses_limit: z.number().int().min(1),
  invite_code_max_expire_days: z.number().int().min(1),
  invite_code_default_max_uses: z.number().int().min(1),
  invite_code_default_max_expire_days: z.number().int().min(1),
  invite_code_preserve_history_enabled: z.boolean(),
  invite_code_audit_enabled: z.boolean(),
})

type BasicAuthFormValues = z.infer<typeof basicAuthSchema>
type InviteConfigKeys =
  | 'invite_code_max_uses_limit'
  | 'invite_code_max_expire_days'
  | 'invite_code_default_max_uses'
  | 'invite_code_default_max_expire_days'
  | 'invite_code_preserve_history_enabled'
  | 'invite_code_audit_enabled'
type BasicAuthInitialValues = Omit<BasicAuthFormValues, InviteConfigKeys> &
  Partial<Pick<BasicAuthFormValues, InviteConfigKeys>>

type BasicAuthSectionProps = {
  defaultValues: BasicAuthInitialValues
}

export function BasicAuthSection({ defaultValues }: BasicAuthSectionProps) {
  const { t } = useTranslation()
  const updateOption = useUpdateOption()

  const formDefaults = useMemo<BasicAuthFormValues>(
    () => ({
      ...defaultValues,
      invite_code_max_uses_limit: defaultValues.invite_code_max_uses_limit ?? 100,
      invite_code_max_expire_days:
        defaultValues.invite_code_max_expire_days ?? 365,
      invite_code_default_max_uses:
        defaultValues.invite_code_default_max_uses ?? 1,
      invite_code_default_max_expire_days:
        defaultValues.invite_code_default_max_expire_days ?? 30,
      invite_code_preserve_history_enabled:
        defaultValues.invite_code_preserve_history_enabled ?? true,
      invite_code_audit_enabled:
        defaultValues.invite_code_audit_enabled ?? false,
      EmailDomainWhitelist: defaultValues.EmailDomainWhitelist.split(',')
        .map((domain) => domain.trim())
        .filter(Boolean)
        .join('\n'),
    }),
    [defaultValues]
  )

  const form = useForm<BasicAuthFormValues>({
    resolver: zodResolver(basicAuthSchema),
    defaultValues: formDefaults,
  })

  useResetForm(form, formDefaults)

  const onSubmit = async (data: BasicAuthFormValues) => {
    const updates: Array<{ key: string; value: string | boolean | number }> = []

    Object.entries(data).forEach(([key, value]) => {
      if (key === 'EmailDomainWhitelist') {
        if (typeof value !== 'string') return
        const domains = value
          .split('\n')
          .map((domain) => domain.trim())
          .filter(Boolean)
          .join(',')
        if (domains !== defaultValues.EmailDomainWhitelist) {
          updates.push({ key, value: domains })
        }
      } else if (value !== defaultValues[key as keyof typeof defaultValues]) {
        updates.push({ key, value })
      }
    })

    for (const update of updates) {
      await updateOption.mutateAsync(update)
    }
  }

  return (
    <SettingsSection
      title={t('Basic Authentication')}
      description={t('Configure password-based login and registration')}
    >
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className='space-y-6'>
          <FormField
            control={form.control}
            name='PasswordLoginEnabled'
            render={({ field }) => (
              <FormItem className='flex flex-row items-center justify-between rounded-lg border p-4'>
                <div className='space-y-0.5'>
                  <FormLabel className='text-base'>
                    {t('Password Login')}
                  </FormLabel>
                  <FormDescription>
                    {t('Allow users to log in with password')}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='RegisterEnabled'
            render={({ field }) => (
              <FormItem className='flex flex-row items-center justify-between rounded-lg border p-4'>
                <div className='space-y-0.5'>
                  <FormLabel className='text-base'>
                    {t('Registration Enabled')}
                  </FormLabel>
                  <FormDescription>
                    {t('Allow new users to register')}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='PasswordRegisterEnabled'
            render={({ field }) => (
              <FormItem className='flex flex-row items-center justify-between rounded-lg border p-4'>
                <div className='space-y-0.5'>
                  <FormLabel className='text-base'>
                    {t('Password Registration')}
                  </FormLabel>
                  <FormDescription>
                    {t('Allow registration with password')}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='InviteOnlyRegistrationEnabled'
            render={({ field }) => (
              <FormItem className='flex flex-row items-center justify-between rounded-lg border p-4'>
                <div className='space-y-0.5'>
                  <FormLabel className='text-base'>
                    {t('Invite-only Registration')}
                  </FormLabel>
                  <FormDescription>
                    {t('Require invite code for registration')}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='invite_code_max_uses_limit'
            render={({ field }) => (
              <FormItem className='rounded-lg border p-4'>
                <FormLabel className='text-base'>
                  {t('Invite Code Max Uses Limit')}
                </FormLabel>
                <FormDescription>
                  {t('Maximum allowed uses for any invite code')}
                </FormDescription>
                <FormControl>
                  <Input
                    type='number'
                    min={1}
                    value={field.value}
                    onChange={(e) => field.onChange(e.target.valueAsNumber || 1)}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='invite_code_max_expire_days'
            render={({ field }) => (
              <FormItem className='rounded-lg border p-4'>
                <FormLabel className='text-base'>
                  {t('Invite Code Max Expire Days')}
                </FormLabel>
                <FormDescription>
                  {t('Maximum allowed expiration days for any invite code')}
                </FormDescription>
                <FormControl>
                  <Input
                    type='number'
                    min={1}
                    value={field.value}
                    onChange={(e) => field.onChange(e.target.valueAsNumber || 1)}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='invite_code_default_max_uses'
            render={({ field }) => (
              <FormItem className='rounded-lg border p-4'>
                <FormLabel className='text-base'>
                  {t('Invite Code Default Max Uses')}
                </FormLabel>
                <FormDescription>
                  {t('Default maximum uses when creating a new invite code')}
                </FormDescription>
                <FormControl>
                  <Input
                    type='number'
                    min={1}
                    value={field.value}
                    onChange={(e) => field.onChange(e.target.valueAsNumber || 1)}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='invite_code_default_max_expire_days'
            render={({ field }) => (
              <FormItem className='rounded-lg border p-4'>
                <FormLabel className='text-base'>
                  {t('Invite Code Default Max Expire Days')}
                </FormLabel>
                <FormDescription>
                  {t('Default expiration days when creating a new invite code')}
                </FormDescription>
                <FormControl>
                  <Input
                    type='number'
                    min={1}
                    value={field.value}
                    onChange={(e) => field.onChange(e.target.valueAsNumber || 1)}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='invite_code_preserve_history_enabled'
            render={({ field }) => (
              <FormItem className='flex flex-row items-center justify-between rounded-lg border p-4'>
                <div className='space-y-0.5'>
                  <FormLabel className='text-base'>
                    {t('Invite Code Preserve History')}
                  </FormLabel>
                  <FormDescription>
                    {t('Keep invite code usage history after code is exhausted')}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='invite_code_audit_enabled'
            render={({ field }) => (
              <FormItem className='flex flex-row items-center justify-between rounded-lg border p-4'>
                <div className='space-y-0.5'>
                  <FormLabel className='text-base'>
                    {t('Invite Code Audit Log')}
                  </FormLabel>
                  <FormDescription>
                    {t('Enable invite code audit logging')}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='EmailVerificationEnabled'
            render={({ field }) => (
              <FormItem className='flex flex-row items-center justify-between rounded-lg border p-4'>
                <div className='space-y-0.5'>
                  <FormLabel className='text-base'>
                    {t('Email Verification')}
                  </FormLabel>
                  <FormDescription>
                    {t('Require email verification for new accounts')}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='EmailDomainRestrictionEnabled'
            render={({ field }) => (
              <FormItem className='flex flex-row items-center justify-between rounded-lg border p-4'>
                <div className='space-y-0.5'>
                  <FormLabel className='text-base'>
                    {t('Email Domain Restriction')}
                  </FormLabel>
                  <FormDescription>
                    {t('Only allow specific email domains')}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='EmailAliasRestrictionEnabled'
            render={({ field }) => (
              <FormItem className='flex flex-row items-center justify-between rounded-lg border p-4'>
                <div className='space-y-0.5'>
                  <FormLabel className='text-base'>
                    {t('Email Alias Restriction')}
                  </FormLabel>
                  <FormDescription>
                    {t('Block email aliases (e.g., user+alias@domain.com)')}
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='EmailDomainWhitelist'
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('Email Domain Whitelist')}</FormLabel>
                <FormControl>
                  <Textarea
                    placeholder={t('example.com&#10;company.com')}
                    rows={4}
                    {...field}
                  />
                </FormControl>
                <FormDescription>
                  {t(
                    'One domain per line (only used when domain restriction is enabled)'
                  )}
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          <Button type='submit' disabled={updateOption.isPending}>
            {updateOption.isPending ? t('Saving...') : t('Save Changes')}
          </Button>
        </form>
      </Form>
    </SettingsSection>
  )
}
