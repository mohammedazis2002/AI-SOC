import { useCallback, useState } from 'react'
import { Loader2, MessageSquareText } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'
import { isAxiosError } from 'axios'
import {
  useAlertFeedbackStatus,
  useSubmitAlertFeedback,
  type FeedbackDecision,
} from '@/hooks/useAlertFeedback'
import { useAppStore } from '@/store/useAppStore'

function parsePlanLines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
}

export function AlertFeedbackPanel({ alertId }: { alertId: string }) {
  const addNotification = useAppStore((s) => s.addNotification)
  const statusQ = useAlertFeedbackStatus(alertId)
  const submitM = useSubmitAlertFeedback(alertId)

  const [decision, setDecision] = useState<FeedbackDecision>('approve')
  const [falsePositive, setFalsePositive] = useState(false)
  const [team, setTeam] = useState('SOC')
  const [confidence, setConfidence] = useState<'low' | 'medium' | 'high'>('medium')
  const [planRating, setPlanRating] = useState<string>('')
  const [comment, setComment] = useState('')
  const [planLines, setPlanLines] = useState('')

  const resetForm = useCallback(() => {
    setDecision('approve')
    setFalsePositive(false)
    setPlanRating('')
    setComment('')
    setPlanLines('')
  }, [])

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const rating: number | undefined =
      planRating === '' ? undefined : Number.parseInt(planRating, 10)
    if (
      planRating !== '' &&
      (rating === undefined || Number.isNaN(rating) || rating < 1 || rating > 5)
    ) {
      addNotification({ type: 'error', message: 'Plan rating must be 1–5 or left blank.' })
      return
    }
    if (decision === 'approve_with_edits') {
      const steps = parsePlanLines(planLines)
      if (steps.length === 0) {
        addNotification({
          type: 'error',
          message: 'For “Approve with edits”, enter at least one action (one per line).',
        })
        return
      }
    }

    submitM.mutate(
      {
        decision,
        false_positive: falsePositive,
        comment: comment.trim() || null,
        plan_rating: rating,
        team: team.trim() || 'SOC',
        confidence,
        analyst_plan:
          decision === 'approve_with_edits' ? parsePlanLines(planLines) : undefined,
      },
      {
        onSuccess: (data) => {
          addNotification({ type: 'success', message: data.message })
          resetForm()
        },
        onError: (err) => {
          const msg =
            err && typeof err === 'object' && 'response' in err
              ? String(
                  (err as { response?: { data?: { detail?: string } } }).response?.data?.detail ??
                    'Failed to submit feedback.'
                )
              : 'Failed to submit feedback.'
          addNotification({ type: 'error', message: msg })
        },
      }
    )
  }

  if (statusQ.isLoading) {
    return (
      <Card id="alert-feedback">
        <CardContent className="py-8 flex justify-center text-slate-500 text-sm">
          <Loader2 className="h-5 w-5 animate-spin mr-2" />
          Checking feedback…
        </CardContent>
      </Card>
    )
  }

  if (statusQ.isError) {
    const is404 = isAxiosError(statusQ.error) && statusQ.error.response?.status === 404
    return (
      <Card id="alert-feedback">
        <CardContent className="py-4 text-sm space-y-1">
          <p className="text-red-700 font-medium">Feedback API returned an error</p>
          <p className="text-slate-600">
            {is404
              ? 'The server could not find this alert in the processed-alerts collection. After updating the API, restart the web backend and refresh. If the alert only exists under source_alert_id, this should be fixed by the latest lookup logic.'
              : 'Check that you are logged in and the API at VITE_API_URL is reachable.'}
          </p>
        </CardContent>
      </Card>
    )
  }

  if (statusQ.data?.submitted) {
    return (
      <Card id="alert-feedback" className="border-emerald-200 bg-emerald-50/40">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm uppercase tracking-wider text-emerald-800 flex items-center gap-2">
            <MessageSquareText className="h-4 w-4" />
            Analyst feedback
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-emerald-900 space-y-1">
          <p>Feedback already submitted for this alert (1:1 with incident).</p>
          <p className="font-mono text-xs text-emerald-800">
            incident_id: {statusQ.data.incident_id}
            {statusQ.data.feedback_id ? ` · feedback_id: ${statusQ.data.feedback_id}` : null}
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card id="alert-feedback">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm uppercase tracking-wider text-slate-500 flex items-center gap-2">
          <MessageSquareText className="h-4 w-4" />
          Analyst feedback
        </CardTitle>
        <p className="text-xs text-slate-500 font-normal leading-relaxed">
          Record plan review for this alert. The server maps it to the same shape as the SOAR feedback
          loop (incident id matches the agentic incident when present, otherwise the alert id).
        </p>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="grid sm:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label htmlFor="fb-decision" className="text-sm font-medium text-slate-700">
                Decision
              </label>
              <select
                id="fb-decision"
                className="h-9 w-full rounded-lg border border-slate-200 px-3 text-sm bg-white"
                value={decision}
                onChange={(e) => setDecision(e.target.value as FeedbackDecision)}
              >
                <option value="approve">Approve (system plan)</option>
                <option value="approve_with_edits">Approve with edits</option>
                <option value="reject">Reject plan</option>
                <option value="escalate">Escalate</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <label htmlFor="fb-confidence" className="text-sm font-medium text-slate-700">
                Confidence
              </label>
              <select
                id="fb-confidence"
                className="h-9 w-full rounded-lg border border-slate-200 px-3 text-sm bg-white"
                value={confidence}
                onChange={(e) => setConfidence(e.target.value as 'low' | 'medium' | 'high')}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </div>
          </div>

          {decision === 'approve_with_edits' && (
            <div className="space-y-1.5">
              <label htmlFor="fb-plan" className="text-sm font-medium text-slate-700">
                Final action list (one per line)
              </label>
              <Textarea
                id="fb-plan"
                placeholder={'e.g.\ncollect auth logs\nisolate host\nreset password'}
                value={planLines}
                onChange={(e) => setPlanLines(e.target.value)}
                className="font-mono text-xs min-h-[100px]"
              />
            </div>
          )}

          <div className="grid sm:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label htmlFor="fb-team" className="text-sm font-medium text-slate-700">
                Team
              </label>
              <input
                id="fb-team"
                className="h-9 w-full rounded-lg border border-slate-200 px-3 text-sm"
                value={team}
                onChange={(e) => setTeam(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <label htmlFor="fb-rating" className="text-sm font-medium text-slate-700">
                Plan rating (optional, 1–5)
              </label>
              <input
                id="fb-rating"
                type="number"
                min={1}
                max={5}
                className="h-9 w-full rounded-lg border border-slate-200 px-3 text-sm"
                placeholder="—"
                value={planRating}
                onChange={(e) => setPlanRating(e.target.value)}
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="fb-comment" className="text-sm font-medium text-slate-700">
              Comment (optional)
            </label>
            <Textarea
              id="fb-comment"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Context for other analysts or training…"
              className="min-h-[72px]"
            />
          </div>

          <div className="flex items-center gap-2">
            <Checkbox
              id="fb-fp"
              checked={falsePositive}
              onCheckedChange={(v) => setFalsePositive(v === true)}
            />
            <label htmlFor="fb-fp" className="text-sm font-normal cursor-pointer">
              False positive (exclude from learning batch)
            </label>
          </div>

          <Button type="submit" disabled={submitM.isPending}>
            {submitM.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Submitting…
              </>
            ) : (
              'Submit feedback'
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
