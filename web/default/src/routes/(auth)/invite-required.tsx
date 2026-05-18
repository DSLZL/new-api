import { useEffect, useState } from 'react'
import { createFileRoute, useNavigate, useSearch } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { AuthLayout } from '@/features/auth/auth-layout'
import { continueOAuthWithInvite } from '@/features/auth/api'
import { saveAffiliateCode } from '@/features/auth/lib/storage'

function InviteRequiredPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const search = useSearch({ from: '/(auth)/invite-required' }) as {
    provider?: string
    redirect?: string
    aff?: string
  }

  const [inviteCode, setInviteCode] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const initial = (search?.aff || '').trim()
    if (!initial) return
    setInviteCode(initial)
    saveAffiliateCode(initial)
  }, [search?.aff])

  const handleSubmit = async () => {
    const code = inviteCode.trim()
    if (!code) {
      toast.error(t('Please enter invite code'))
      return
    }

    setLoading(true)
    try {
      const res = await continueOAuthWithInvite(code)
      if (res?.success) {
        saveAffiliateCode(code)
        toast.success(t('Signed in successfully!'))
        const target = search?.redirect || '/dashboard'
        navigate({ to: target as never, replace: true })
        return
      }

      const businessCode = (res?.data as { code?: string } | undefined)?.code
      if (businessCode === 'INVITE_CODE_INVALID') {
        toast.error(t('Invalid invite code'))
        return
      }
      if (businessCode === 'OAUTH_PENDING_EXPIRED') {
        toast.error(t('OAuth session expired, please try again'))
        navigate({ to: '/sign-in', replace: true })
        return
      }
      if (businessCode === 'OAUTH_PENDING_NOT_FOUND') {
        toast.error(t('OAuth session not found, please try again'))
        navigate({ to: '/sign-in', replace: true })
        return
      }
      toast.error(res?.message || t('OAuth failed'))
    } catch (_error) {
      toast.error(t('OAuth failed'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthLayout>
      <div className='w-full space-y-6'>
        <div className='space-y-2'>
          <h2 className='text-center text-2xl font-semibold tracking-tight sm:text-left'>
            {t('Invite code is required for registration')}
          </h2>
          <p className='text-muted-foreground text-left text-sm sm:text-base'>
            {t('Enter invite code to complete registration')}
          </p>
        </div>

        <div className='grid gap-4'>
            <Input
              value={inviteCode}
              onChange={(event) => setInviteCode(event.target.value)}
              placeholder={t('Use your inviter code')}
              autoComplete='off'
            />
          <Button onClick={handleSubmit} disabled={loading}>
            {loading ? t('Loading...') : t('Confirm')}
          </Button>
        </div>
      </div>
    </AuthLayout>
  )
}

export const Route = createFileRoute('/(auth)/invite-required')({
  component: InviteRequiredPage,
})
