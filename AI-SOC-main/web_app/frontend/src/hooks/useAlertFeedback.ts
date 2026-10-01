import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { isAxiosError } from 'axios'

export interface AlertFeedbackStatusResponse {
  submitted: boolean
  feedback_id: string | null
  incident_id: string
}

export type FeedbackDecision = 'approve' | 'approve_with_edits' | 'reject' | 'escalate'

export interface AlertFeedbackSubmitBody {
  decision: FeedbackDecision
  false_positive: boolean
  comment?: string | null
  plan_rating?: number | null
  analyst_plan?: string[] | null
  team?: string
  confidence?: 'low' | 'medium' | 'high'
}

export function useAlertFeedbackStatus(alertId: string | undefined) {
  return useQuery({
    queryKey: ['alerts', 'feedback', alertId],
    queryFn: async (): Promise<AlertFeedbackStatusResponse> => {
      const { data } = await api.get<AlertFeedbackStatusResponse>(
        `/alerts/${encodeURIComponent(alertId!)}/feedback`
      )
      return data
    },
    enabled: Boolean(alertId),
    staleTime: 15_000,
  })
}

export function useSubmitAlertFeedback(alertId: string | undefined) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: AlertFeedbackSubmitBody) => {
      const { data } = await api.post<{
        status: string
        feedback_id: string
        incident_id: string
        message: string
      }>(`/alerts/${encodeURIComponent(alertId!)}/feedback`, {
        decision: body.decision,
        false_positive: body.false_positive,
        comment: body.comment || null,
        plan_rating: body.plan_rating ?? null,
        analyst_plan: body.analyst_plan ?? null,
        team: body.team ?? 'SOC',
        confidence: body.confidence ?? 'medium',
      })
      return data
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['alerts', 'feedback', alertId] })
    },
    onError: (e) => {
      if (isAxiosError(e) && e.response?.status === 409) {
        void qc.invalidateQueries({ queryKey: ['alerts', 'feedback', alertId] })
      }
    },
  })
}
