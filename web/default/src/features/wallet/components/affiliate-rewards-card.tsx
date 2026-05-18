import { History, RotateCw, Settings2, Share2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { formatQuota } from '@/lib/format'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { CopyButton } from '@/components/copy-button'
import { formatTimestampToDate } from '@/lib/format'
import type { AffiliateCodeDetail, UserWalletData } from '../types'

interface AffiliateRewardsCardProps {
  user: UserWalletData | null
  inviteCode: AffiliateCodeDetail | null
  affiliateLink: string
  onTransfer: () => void
  onManageInviteCode: () => void
  loading?: boolean
}

export function AffiliateRewardsCard({
  user,
  inviteCode,
  affiliateLink,
  onTransfer,
  onManageInviteCode,
  loading,
}: AffiliateRewardsCardProps) {
  const { t } = useTranslation()
  if (loading) {
    return (
      <Card className='bg-muted/20 py-0'>
        <CardContent className='grid gap-4 p-3 sm:p-4 lg:grid-cols-[minmax(220px,1fr)_minmax(220px,0.72fr)_minmax(320px,1.15fr)] lg:items-center'>
          <div>
            <Skeleton className='h-5 w-32' />
            <Skeleton className='mt-2 h-4 w-48' />
          </div>
          <Skeleton className='h-14 rounded-lg' />
          <Skeleton className='h-10 rounded-lg' />
        </CardContent>
      </Card>
    )
  }

  const hasRewards = (user?.aff_quota ?? 0) > 0
  const usageText = inviteCode
    ? `${inviteCode.used_count}/${inviteCode.max_uses}`
    : '-'

  return (
    <Card className='bg-muted/20 py-0'>
      <CardContent className='grid gap-4 p-3 sm:p-4 lg:grid-cols-[minmax(200px,1fr)_minmax(220px,0.75fr)_minmax(320px,1.05fr)] lg:items-center'>
        <div className='flex min-w-0 items-center gap-2.5'>
          <div className='bg-background flex size-8 shrink-0 items-center justify-center rounded-lg border'>
            <Share2 className='text-muted-foreground size-4' />
          </div>
          <div className='min-w-0'>
            <h3 className='truncate text-sm font-semibold'>
              {t('Referral Program')}
            </h3>
            <p className='text-muted-foreground line-clamp-1 text-xs'>
              {t(
                'Earn rewards when your referrals add funds. Transfer accumulated rewards to your balance anytime.'
              )}
            </p>
          </div>
        </div>

        <div className='grid grid-cols-3 gap-1.5 text-center'>
          {[
            [t('Pending'), formatQuota(user?.aff_quota ?? 0)],
            [t('Total Earned'), formatQuota(user?.aff_history_quota ?? 0)],
            [t('Invites'), String(user?.aff_count ?? 0)],
          ].map(([label, value]) => (
            <div key={label}>
              <div className='text-muted-foreground truncate text-[10px] font-medium tracking-wider uppercase'>
                {label}
              </div>
              <div className='mt-0.5 truncate text-sm font-semibold tabular-nums'>
                {value}
              </div>
            </div>
          ))}
        </div>

        <div className='grid gap-3'>
          <div className='flex flex-wrap items-center gap-2'>
            <Badge variant='outline' className='font-mono'>
              {t('Usage')}: {usageText}
            </Badge>
            <Badge variant='outline'>
              {t('Expires at')}: {formatTimestampToDate(inviteCode?.expires_at)}
            </Badge>
            <Button
              variant='outline'
              size='sm'
              className='ml-auto'
              onClick={onManageInviteCode}
            >
              <Settings2 className='mr-1 size-4' />
              {t('Manage invite code')}
            </Button>
          </div>
          <div className='flex items-center gap-2'>
            <Input
              value={inviteCode?.code || user?.aff_code || ''}
              readOnly
              className='border-muted bg-background/70 h-9 min-w-0 flex-1 font-mono text-xs'
            />
            <CopyButton
              value={inviteCode?.code || user?.aff_code || ''}
              variant='outline'
              className='bg-background size-9 shrink-0'
              iconClassName='size-4'
              tooltip={t('Copy invite code')}
              aria-label={t('Copy invite code')}
            />
          </div>
          <div className='flex items-center gap-2'>
            <Input
              value={affiliateLink}
              readOnly
              className='border-muted bg-background/70 h-9 min-w-0 flex-1 font-mono text-xs'
            />
            <CopyButton
              value={affiliateLink}
              variant='outline'
              className='bg-background size-9 shrink-0'
              iconClassName='size-4'
              tooltip={t('Copy referral link')}
              aria-label={t('Copy referral link')}
            />
            <Button
              variant='outline'
              size='icon-sm'
              className='shrink-0'
              onClick={onManageInviteCode}
              aria-label={t('View invite code history')}
            >
              <History className='size-4' />
            </Button>
            <Button
              variant='outline'
              size='icon-sm'
              className='shrink-0'
              onClick={onManageInviteCode}
              aria-label={t('Refresh code')}
            >
              <RotateCw className='size-4' />
            </Button>
            {hasRewards && (
              <Button
                onClick={onTransfer}
                className='h-9 shrink-0 px-3'
                size='sm'
              >
                {t('Transfer to Balance')}
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
