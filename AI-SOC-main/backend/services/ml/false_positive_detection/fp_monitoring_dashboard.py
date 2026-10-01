"""
FP Detector Monitoring Dashboard

Gradio dashboard for tracking FP detection performance
"""

import gradio as gr
from pymongo import MongoClient
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
from collections import defaultdict
import pandas as pd

# Initialize
db = MongoClient()['soar_db']


class FPMonitoring:
    """FP detector monitoring and analytics"""
    
    def get_overview_metrics(self) -> Dict:
        """Get overall FP detection metrics"""
        total_alerts = db.alerts.count_documents({'fp_analysis': {'$exists': True}})
        
        auto_closed = db.alerts.count_documents({
            'fp_analysis.recommendation.action': 'auto_close'
        })
        
        suppressed = db.alerts.count_documents({
            'fp_analysis.recommendation.action': 'suppress'
        })
        
        investigated = db.alerts.count_documents({
            'fp_analysis.recommendation.action': 'investigate'
        })
        
        return {
            'total_alerts': total_alerts,
            'auto_closed': auto_closed,
            'suppressed': suppressed,
            'investigated': investigated,
            'auto_close_rate': auto_closed / total_alerts if total_alerts > 0 else 0,
            'suppression_rate': suppressed / total_alerts if total_alerts > 0 else 0
        }
    
    def get_accuracy_metrics(self) -> Dict:
        """Calculate model accuracy from analyst feedback"""
        # Get alerts with both model prediction and analyst verdict
        pipeline = [
            {'$match': {
                'fp_analysis': {'$exists': True},
                'analyst_verdict': {'$exists': True}
            }},
            {'$project': {
                'model_fp': {'$gte': ['$fp_analysis.fp_score', 0.7]},
                'analyst_fp': {'$eq': ['$analyst_verdict', 'false_positive']}
            }}
        ]
        
        alerts = list(db.alerts.aggregate(pipeline))
        
        if not alerts:
            return {
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0,
                'accuracy': 0.0,
                'total_labeled': 0
            }
        
        tp = sum(1 for a in alerts if a['model_fp'] and a['analyst_fp'])  # True Positive (FP predictions)
        fp = sum(1 for a in alerts if a['model_fp'] and not a['analyst_fp'])  # False Positive
        fn = sum(1 for a in alerts if not a['model_fp'] and a['analyst_fp'])  # False Negative
        tn = sum(1 for a in alerts if not a['model_fp'] and not a['analyst_fp'])  # True Negative
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / len(alerts)
        
        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'accuracy': accuracy,
            'total_labeled': len(alerts),
            'true_positives': tp,
            'false_positives': fp,
            'false_negatives': fn,
            'true_negatives': tn
        }
    
    def get_noisy_rules(self, limit=10) -> list:
        """Get top noisy rules"""
        noisy = list(db.noisy_rules.find({}).sort('fp_rate', -1).limit(limit))
        
        return [
            {
                'rule_id': r.get('rule_id', 'N/A'),
                'rule_name': r.get('rule_name', 'Unknown')[:50],
                'fp_rate': f"{r.get('fp_rate', 0)*100:.1f}%",
                'total_count': r.get('total', 0),
                'fp_count': r.get('fp_count', 0)
            }
            for r in noisy
        ]
    
    def create_fp_trend_chart(self, days=30):
        """Create FP detection trend chart"""
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_ms = int(cutoff.timestamp() * 1000)
        
        pipeline = [
            {'$match': {
                'fp_analysis': {'$exists': True},
                'time': {'$gte': cutoff_ms}
            }},
            {'$project': {
                'date': {
                    '$dateToString': {
                        'format': '%Y-%m-%d',
                        'date': {'$toDate': '$time'}
                    }
                },
                'action': '$fp_analysis.recommendation.action'
            }},
            {'$group': {
                '_id': {'date': '$date', 'action': '$action'},
                'count': {'$sum': 1}
            }},
            {'$sort': {'_id.date': 1}}
        ]
        
        results = list(db.alerts.aggregate(pipeline))
        
        # Organize data
        dates = sorted(set(r['_id']['date'] for r in results))
        auto_closed_data = []
        suppressed_data = []
        investigated_data = []
        
        for date in dates:
            auto_closed = sum(r['count'] for r in results if r['_id']['date'] == date and r['_id']['action'] == 'auto_close')
            suppressed = sum(r['count'] for r in results if r['_id']['date'] == date and r['_id']['action'] == 'suppress')
            investigated = sum(r['count'] for r in results if r['_id']['date'] == date and r['_id']['action'] == 'investigate')
            
            auto_closed_data.append(auto_closed)
            suppressed_data.append(suppressed)
            investigated_data.append(investigated)
        
        # Create chart
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=dates, y=auto_closed_data,
            name='Auto-Closed',
            mode='lines+markers',
            line=dict(color='red')
        ))
        
        fig.add_trace(go.Scatter(
            x=dates, y=suppressed_data,
            name='Suppressed',
            mode='lines+markers',
            line=dict(color='orange')
        ))
        
        fig.add_trace(go.Scatter(
            x=dates, y=investigated_data,
            name='Investigated',
            mode='lines+markers',
            line=dict(color='green')
        ))
        
        fig.update_layout(
            title=f'FP Detection Trends ({days} Days)',
            xaxis_title='Date',
            yaxis_title='Alert Count',
            hovermode='x unified'
        )
        
        return fig
    
    def create_accuracy_over_time_chart(self):
        """Track model accuracy improvement over time"""
        # Group by week
        pipeline = [
            {'$match': {
                'analyst_verdict': {'$exists': True},
                'fp_analysis': {'$exists': True}
            }},
            {'$project': {
                'week': {
                    '$dateToString': {
                        'format': '%Y-W%V',
                        'date': {'$toDate': '$reviewed_at'}
                    }
                },
                'correct': {
                    '$eq': [
                        {'$gte': ['$fp_analysis.fp_score', 0.7]},
                        {'$eq': ['$analyst_verdict', 'false_positive']}
                    ]
                }
            }},
            {'$group': {
                '_id': '$week',
                'total': {'$sum': 1},
                'correct': {'$sum': {'$cond': ['$correct', 1, 0]}}
            }},
            {'$project': {
                'week': '$_id',
                'accuracy': {'$divide': ['$correct', '$total']}
            }},
            {'$sort': {'week': 1}}
        ]
        
        results = list(db.alerts.aggregate(pipeline))
        
        if not results:
            return None
        
        weeks = [r['week'] for r in results]
        accuracy = [r['accuracy'] * 100 for r in results]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=weeks,
            y=accuracy,
            mode='lines+markers',
            name='Accuracy',
            line=dict(color='blue', width=3)
        ))
        
        fig.add_hline(y=85, line_dash="dash", line_color="green", annotation_text="Target: 85%")
        
        fig.update_layout(
            title='Model Accuracy Over Time',
            xaxis_title='Week',
            yaxis_title='Accuracy (%)',
            yaxis_range=[0, 100]
        )
        
        return fig


# Create dashboard
monitor = FPMonitoring()


def create_dashboard():
    """Create monitoring dashboard"""
    
    with gr.Blocks(title="FP Detector Monitoring", theme=gr.themes.Soft()) as demo:
        gr.Markdown("# 📊 FP Detector Monitoring Dashboard")
        
        with gr.Tab("📈 Performance"):
            gr.Markdown("### Overall Metrics")
            
            with gr.Row():
                total_alerts_num = gr.Number(label="Total Alerts Analyzed", precision=0)
                auto_closed_num = gr.Number(label="Auto-Closed", precision=0)
                suppressed_num = gr.Number(label="Suppressed", precision=0)
                investigated_num = gr.Number(label="Investigated", precision=0)
            
            with gr.Row():
                auto_close_rate = gr.Number(label="Auto-Close Rate (%)", precision=1)
                suppression_rate = gr.Number(label="Suppression Rate (%)", precision=1)
            
            gr.Markdown("### Model Accuracy")
            
            with gr.Row():
                precision_num = gr.Number(label="Precision", precision=3)
                recall_num = gr.Number(label="Recall", precision=3)
                f1_num = gr.Number(label="F1-Score", precision=3)
                accuracy_num = gr.Number(label="Accuracy", precision=3)
            
            with gr.Row():
                labeled_count = gr.Number(label="Labeled Alerts", precision=0)
            
            gr.Markdown("### Trend Charts")
            
            fp_trend_chart = gr.Plot(label="FP Detection Trends")
            accuracy_chart = gr.Plot(label="Accuracy Over Time")
            
            refresh_perf_btn = gr.Button("🔄 Refresh Performance Metrics", variant="primary")
        
        with gr.Tab("🎯 Noisy Rules"):
            gr.Markdown("### Top Noisy Rules")
            gr.Markdown("Rules with high false positive rates that should be reviewed")
            
            noisy_rules_table = gr.Dataframe(
                headers=["Rule ID", "Rule Name", "FP Rate", "Total Count", "FP Count"],
                label="Noisy Rules",
                interactive=False
            )
            
            refresh_rules_btn = gr.Button("🔄 Refresh Noisy Rules", variant="primary")
        
        # Event handlers
        def load_performance():
            """Load performance metrics"""
            overview = monitor.get_overview_metrics()
            accuracy = monitor.get_accuracy_metrics()
            
            return (
                overview['total_alerts'],
                overview['auto_closed'],
                overview['suppressed'],
                overview['investigated'],
                overview['auto_close_rate'] * 100,
                overview['suppression_rate'] * 100,
                accuracy['precision'],
                accuracy['recall'],
                accuracy['f1_score'],
                accuracy['accuracy'],
                accuracy['total_labeled'],
                monitor.create_fp_trend_chart(),
                monitor.create_accuracy_over_time_chart()
            )
        
        def load_noisy_rules():
            """Load noisy rules"""
            rules = monitor.get_noisy_rules()
            
            if not rules:
                return [[]]
            
            return [[r['rule_id'], r['rule_name'], r['fp_rate'], r['total_count'], r['fp_count']] for r in rules]
        
        # Initial load
        demo.load(
            load_performance,
            outputs=[
                total_alerts_num, auto_closed_num, suppressed_num, investigated_num,
                auto_close_rate, suppression_rate,
                precision_num, recall_num, f1_num, accuracy_num, labeled_count,
                fp_trend_chart, accuracy_chart
            ]
        )
        
        demo.load(load_noisy_rules, outputs=[noisy_rules_table])
        
        # Refresh handlers
        refresh_perf_btn.click(
            load_performance,
            outputs=[
                total_alerts_num, auto_closed_num, suppressed_num, investigated_num,
                auto_close_rate, suppression_rate,
                precision_num, recall_num, f1_num, accuracy_num, labeled_count,
                fp_trend_chart, accuracy_chart
            ]
        )
        
        refresh_rules_btn.click(load_noisy_rules, outputs=[noisy_rules_table])
    
    return demo


if __name__ == "__main__":
    # Launch dashboard
    demo = create_dashboard()
    demo.launch(
        server_name="0.0.0.0",
        server_port=7861,
        share=False
    )
