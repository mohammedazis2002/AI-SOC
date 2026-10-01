"""
Analyst Labeling UI for False Positive Feedback

Gradio-based interface for analysts to label alerts
"""

import gradio as gr
from pymongo import MongoClient
from datetime import datetime
import requests
from typing import Optional, Dict

# Initialize
db = MongoClient()['soar_db']
FP_DETECTOR_URL = "http://localhost:5006"


class LabelingInterface:
    """Analyst labeling interface for FP feedback"""
    
    def __init__(self):
        self.current_alert = None
        self.current_index = 0
        
    def get_next_unlabeled(self) -> Optional[Dict]:
        """Fetch next alert without analyst verdict"""
        alert = db.alerts.find_one({
            'analyst_verdict': {'$exists': False},
            'fp_analysis': {'$exists': True}
        })
        
        if alert:
            self.current_alert = alert
        
        return alert
    
    def get_progress(self) -> tuple:
        """Get labeling progress"""
        total_with_fp = db.alerts.count_documents({'fp_analysis': {'$exists': True}})
        labeled = db.alerts.count_documents({'analyst_verdict': {'$exists': True}})
        
        return labeled, total_with_fp
    
    def format_alert_details(self, alert: Optional[Dict]) -> str:
        """Format alert details for display"""
        if not alert:
            return "No more unlabeled alerts!"
        
        return f"""
**Alert ID:** {alert.get('alert_id', 'N/A')}

**Time:** {datetime.fromtimestamp(alert.get('time', 0)/1000).strftime('%Y-%m-%d %H:%M:%S')}

**Severity:** {self._get_severity_text(alert.get('severity_id', 0))}

**Rule:** {alert.get('finding', {}).get('title', 'Unknown')} 
(Rule ID: {alert.get('unmapped', {}).get('wazuh_rule_id', 'N/A')})

**Source:** {alert.get('src_endpoint', {}).get('ip', 'N/A')} 
({alert.get('src_endpoint', {}).get('hostname', 'N/A')})

**Destination:** {alert.get('dst_endpoint', {}).get('hostname', 'N/A')}

**Description:**
{alert.get('finding', {}).get('desc', 'No description available')[:300]}
"""
    
    def format_fp_analysis(self, alert: Optional[Dict]) -> str:
        """Format FP analysis for display"""
        if not alert or 'fp_analysis' not in alert:
            return "No FP analysis available"
        
        fp = alert['fp_analysis']
        
        prediction = "FALSE POSITIVE" if fp['fp_score'] >= 0.7 else "TRUE POSITIVE"
        color = "🔴" if fp['fp_score'] >= 0.7 else "🟢"
        
        reasons_text = "\n".join(f"• {r}" for r in fp.get('reasons', []))
        
        return f"""
{color} **AI Prediction:** {prediction}

**FP Score:** {fp['fp_score']:.2f} (0 = TP, 1 = FP)

**Confidence:** {fp['confidence']:.2f}

**Method:** {fp.get('method', 'unknown')}

**Reasons:**
{reasons_text}

**Recommendation:** {fp['recommendation']['action'].upper()}
"""
    
    def format_similar_fps(self, alert: Optional[Dict]) -> str:
        """Format similar FPs for display"""
        if not alert or 'fp_analysis' not in alert:
            return "No similar FPs"
        
        similar = alert['fp_analysis'].get('similar_fps', [])
        
        if not similar:
            return "No similar false positives found in the last 30 days"
        
        items = []
        for s in similar:
            time_str = datetime.fromtimestamp(s['time']/1000).strftime('%Y-%m-%d')
            items.append(f"• {time_str} - Analyst: {s['analyst']} - Reason: {s['reason']}")
        
        return f"**{len(similar)} similar FPs found:**\n\n" + "\n".join(items)
    
    def submit_label(self, verdict: str, reason: str, notes: str, analyst_name: str) -> str:
        """Submit analyst verdict"""
        if not self.current_alert:
            return "❌ No alert to label!"
        
        if not verdict:
            return "❌ Please select a verdict (True Positive or False Positive)"
        
        if not analyst_name:
            return "❌ Please enter your name"
        
        try:
            # Update database
            db.alerts.update_one(
                {'alert_id': self.current_alert['alert_id']},
                {'$set': {
                    'analyst_verdict': 'false_positive' if verdict == 'False Positive' else 'true_positive',
                    'review_reason': reason,
                    'review_notes': notes,
                    'reviewed_at': datetime.now(),
                    'reviewed_by': analyst_name
                }}
            )
            
            # Submit feedback to FP detector
            fp_analysis = self.current_alert.get('fp_analysis', {})
            model_prediction = 'false_positive' if fp_analysis.get('fp_score', 0) >= 0.7 else 'true_positive'
            analyst_verdict = 'false_positive' if verdict == 'False Positive' else 'true_positive'
            
            requests.post(f'{FP_DETECTOR_URL}/feedback', json={
                'alert_id': self.current_alert['alert_id'],
                'model_prediction': model_prediction,
                'analyst_verdict': analyst_verdict,
                'analyst': analyst_name,
                'reason': reason
            })
            
            # Get next alert
            next_alert = self.get_next_unlabeled()
            
            labeled, total = self.get_progress()
            
            return (
                f"✅ **Labeled successfully!**\n\n"
                f"Progress: {labeled}/{total} ({labeled/total*100:.1f}%)\n\n"
                f"Loading next alert..."
            )
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def skip_alert(self) -> str:
        """Skip current alert"""
        next_alert = self.get_next_unlabeled()
        return "⏭️ Skipped to next alert"
    
    def _get_severity_text(self, severity_id: int) -> str:
        """Convert severity ID to text"""
        mapping = {
            1: "🔵 Low",
            2: "🟡 Medium",
            3: "🟠 High",
            4: "🔴 Critical"
        }
        return mapping.get(severity_id, "Unknown")


# Create interface
labeler = LabelingInterface()


def create_labeling_ui():
    """Create Gradio labeling interface"""
    
    with gr.Blocks(title="FP Labeling Assistant", theme=gr.themes.Soft()) as demo:
        gr.Markdown("# 🎯 False Positive Labeling Assistant")
        
        # Progress bar
        with gr.Row():
            progress_text = gr.Markdown("Loading...")
        
        with gr.Row():
            # Left column: Alert details
            with gr.Column(scale=2):
                gr.Markdown("### 📋 Alert Details")
                alert_details = gr.Markdown("Loading first alert...")
                
            # Right column: AI Analysis
            with gr.Column(scale=1):
                gr.Markdown("### 🤖 AI Analysis")
                fp_analysis = gr.Markdown("Loading...")
                
                gr.Markdown("### 📊 Similar FPs")
                similar_fps = gr.Markdown("Loading...")
        
        # Labeling section
        gr.Markdown("---")
        gr.Markdown("### ✍️ Your Verdict")
        
        with gr.Row():
            verdict = gr.Radio(
                choices=["True Positive", "False Positive"],
                label="Verdict",
                value=None
            )
        
        with gr.Row():
            reason = gr.Dropdown(
                choices=[
                    "Scheduled vulnerability scan",
                    "Legitimate admin activity",
                    "Monitoring/health check",
                    "Business-approved automation",
                    "Test environment activity",
                    "Scanner traffic",
                    "Known benign process",
                    "Configuration change",
                    "Other (see notes)"
                ],
                label="Reason (for False Positives)",
                value="Scheduled vulnerability scan"
            )
        
        with gr.Row():
            notes = gr.Textbox(
                label="Additional Notes (optional)",
                placeholder="Any additional context...",
                lines=2
            )
        
        with gr.Row():
            analyst_name = gr.Textbox(
                label="Your Name",
                placeholder="e.g., jane.doe",
                value=""
            )
        
        # Action buttons
        with gr.Row():
            skip_btn = gr.Button("⏭️ Skip", variant="secondary")
            submit_btn = gr.Button("✅ Submit & Next", variant="primary")
        
        status_msg = gr.Markdown("")
        
        # Event handlers
        def load_alert():
            """Load alert and update UI"""
            alert = labeler.get_next_unlabeled()
            labeled, total = labeler.get_progress()
            
            return (
                f"**Progress:** {labeled}/{total} labeled ({labeled/total*100:.1f}% complete)",
                labeler.format_alert_details(alert),
                labeler.format_fp_analysis(alert),
                labeler.format_similar_fps(alert),
                ""  # Clear status
            )
        
        # Initial load
        demo.load(
            load_alert,
            outputs=[progress_text, alert_details, fp_analysis, similar_fps, status_msg]
        )
        
        # Submit handler
        def on_submit(verd, reas, note, analyst):
            status = labeler.submit_label(verd, reas, note, analyst)
            alert = labeler.current_alert
            labeled, total = labeler.get_progress()
            
            return (
                f"**Progress:** {labeled}/{total} labeled ({labeled/total*100:.1f}% complete)",
                labeler.format_alert_details(alert),
                labeler.format_fp_analysis(alert),
                labeler.format_similar_fps(alert),
                status,
                None,  # Clear verdict
                ""     # Clear notes
            )
        
        submit_btn.click(
            on_submit,
            inputs=[verdict, reason, notes, analyst_name],
            outputs=[progress_text, alert_details, fp_analysis, similar_fps, status_msg, verdict, notes]
        )
        
        # Skip handler
        def on_skip():
            status = labeler.skip_alert()
            alert = labeler.current_alert
            labeled, total = labeler.get_progress()
            
            return (
                f"**Progress:** {labeled}/{total} labeled ({labeled/total*100:.1f}% complete)",
                labeler.format_alert_details(alert),
                labeler.format_fp_analysis(alert),
                labeler.format_similar_fps(alert),
                status
            )
        
        skip_btn.click(
            on_skip,
            outputs=[progress_text, alert_details, fp_analysis, similar_fps, status_msg]
        )
    
    return demo


if __name__ == "__main__":
    # Launch UI
    demo = create_labeling_ui()
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False
    )
