import z from 'zod'
import { createFileRoute } from '@tanstack/react-router'
import { Rankings } from '@/features/rankings'

const rankingsSearchSchema = z.object({
  metric: z
    .enum(['balance', 'invites', 'consumption'])
    .optional()
    .catch(undefined),
  period: z.enum(['daily', 'total']).optional().catch(undefined),
})

export const Route = createFileRoute('/rankings/')({
  validateSearch: rankingsSearchSchema,
  component: Rankings,
})
