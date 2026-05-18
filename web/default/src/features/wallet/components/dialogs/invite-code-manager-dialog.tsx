import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { formatTimestampToDate } from '@/lib/format'
import type { AffiliateCodeDetail, InviteCodeRefreshPayload } from '../../types'

interface InviteCodeManagerDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  inviteCode: AffiliateCodeDetail | null
  history: AffiliateCodeDetail[]
  historyLoading: boolean
  saving: boolean
  refreshing: boolean
  refreshResult: InviteCodeRefreshPayload | null
  onUpdateRules: (input: { maxUses: number; expireDays: number }) => Promise<boolean>
  onRefresh: () => Promise<boolean>
  onLoadHistory: () => Promise<void>
  onClearRefreshResult: () => void
}

const SECONDS_PER_DAY = 86400

function getExpireDays(inviteCode: AffiliateCodeDetail | null): number {
  if (!inviteCode?.expires_at) return 1
  const now = Math.floor(Date.now() / 1000)
  const diff = inviteCode.expires_at - now
  return Math.max(1, Math.ceil(diff / SECONDS_PER_DAY))
}

function getStatusLabel(status: string | undefined, t: (key: string) => string): string {
  switch (status) {
    case 'active':
      return t('Active')
    case 'invalidated':
      return t('Invalidated')
    case 'expired':
      return t('Expired')
    case 'exhausted':
      return t('Exhausted')
    default:
      return status || '-'
  }
}

export function InviteCodeManagerDialog({
  open,
  onOpenChange,
  inviteCode,
  history,
  historyLoading,
  saving,
  refreshing,
  refreshResult,
  onUpdateRules,
  onRefresh,
  onLoadHistory,
  onClearRefreshResult,
}: InviteCodeManagerDialogProps) {
  const { t } = useTranslation()
  const [maxUses, setMaxUses] = useState(1)
  const [expireDays, setExpireDays] = useState(1)

  useEffect(() => {
    if (!inviteCode) return
    setMaxUses(Math.max(1, inviteCode.max_uses))
    setExpireDays(getExpireDays(inviteCode))
  }, [inviteCode])

  useEffect(() => {
    if (!open) {
      onClearRefreshResult()
      return
    }
    void onLoadHistory()
  }, [open, onClearRefreshResult, onLoadHistory])

  const usageLabel = useMemo(() => {
    if (!inviteCode) return '-'
    return `${inviteCode.used_count}/${inviteCode.max_uses}`
  }, [inviteCode])

  const handleSave = async () => {
    const ok = await onUpdateRules({
      maxUses: Math.max(1, Math.floor(maxUses)),
      expireDays: Math.max(1, Math.floor(expireDays)),
    })
    if (ok) {
      await onLoadHistory()
    }
  }

  const handleRefresh = async () => {
    const ok = await onRefresh()
    if (ok) {
      await onLoadHistory()
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className='max-w-3xl p-0'>
        <DialogHeader className='p-6 pb-0'>
          <DialogTitle>{t('Manage invite code')}</DialogTitle>
          <DialogDescription>
            {t('Adjust invite code usage rules, refresh the code, and review previous codes.')}
          </DialogDescription>
        </DialogHeader>

        <div className='grid gap-6 p-6'>
          <div className='grid gap-4 rounded-xl border p-4 md:grid-cols-4'>
            <div>
              <div className='text-muted-foreground text-xs'>{t('Current code')}</div>
              <div className='mt-1 font-mono text-sm font-semibold'>
                {inviteCode?.code || '-'}
              </div>
            </div>
            <div>
              <div className='text-muted-foreground text-xs'>{t('Usage')}</div>
              <div className='mt-1 text-sm font-semibold'>{usageLabel}</div>
            </div>
            <div>
              <div className='text-muted-foreground text-xs'>{t('Expires at')}</div>
              <div className='mt-1 text-sm font-semibold'>
                {formatTimestampToDate(inviteCode?.expires_at)}
              </div>
            </div>
            <div>
              <div className='text-muted-foreground text-xs'>{t('Status')}</div>
              <div className='mt-1 text-sm font-semibold'>
                {getStatusLabel(inviteCode?.status, t)}
              </div>
            </div>
          </div>

          <div className='grid gap-4 rounded-xl border p-4 md:grid-cols-2'>
            <div className='space-y-2'>
              <label className='text-sm font-medium'>{t('Max uses')}</label>
              <Input
                type='number'
                min={1}
                value={maxUses}
                onChange={(event) =>
                  setMaxUses(Math.max(1, event.target.valueAsNumber || 1))
                }
              />
            </div>
            <div className='space-y-2'>
              <label className='text-sm font-medium'>{t('Expire in days')}</label>
              <Input
                type='number'
                min={1}
                value={expireDays}
                onChange={(event) =>
                  setExpireDays(Math.max(1, event.target.valueAsNumber || 1))
                }
              />
            </div>
            <div className='text-muted-foreground md:col-span-2 text-xs'>
              {t('Saving rules updates the current code immediately. Refreshing replaces the code and invalidates the previous one.')}
            </div>
            {refreshResult?.previous && (
              <div className='rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm md:col-span-2'>
                <div className='font-medium'>{t('Previous code invalidated')}</div>
                <div className='mt-1 font-mono text-xs'>
                  {refreshResult.previous.code} {'->'} {refreshResult.current.code}
                </div>
              </div>
            )}
          </div>

          <div className='rounded-xl border p-4'>
            <div className='mb-3 flex items-center justify-between gap-3'>
              <div>
                <div className='text-sm font-medium'>{t('Invite code history')}</div>
                <div className='text-muted-foreground text-xs'>
                  {t('Past codes remain visible here when history retention is enabled.')}
                </div>
              </div>
              <Button
                type='button'
                variant='outline'
                size='sm'
                onClick={() => void onLoadHistory()}
                disabled={historyLoading}
              >
                {historyLoading ? t('Loading...') : t('Refresh history')}
              </Button>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('Code')}</TableHead>
                  <TableHead>{t('Status')}</TableHead>
                  <TableHead>{t('Usage')}</TableHead>
                  <TableHead>{t('Expires at')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {history.length > 0 ? (
                  history.map((item) => (
                    <TableRow key={`${item.code}-${item.activated_at ?? item.expires_at}`}>
                      <TableCell className='font-mono text-xs'>{item.code}</TableCell>
                      <TableCell>{getStatusLabel(item.status, t)}</TableCell>
                      <TableCell>{`${item.used_count}/${item.max_uses}`}</TableCell>
                      <TableCell>{formatTimestampToDate(item.expires_at)}</TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={4} className='text-muted-foreground text-center'>
                      {historyLoading ? t('Loading...') : t('No invite code history yet')}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </div>

        <DialogFooter>
          <Button
            type='button'
            variant='outline'
            onClick={() => void handleRefresh()}
            disabled={refreshing}
          >
            {refreshing ? t('Refreshing...') : t('Refresh code')}
          </Button>
          <Button type='button' onClick={() => void handleSave()} disabled={saving}>
            {saving ? t('Saving...') : t('Save invite settings')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
