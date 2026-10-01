// MongoDB Initialization Script for SOAR Platform

db = db.getSiblingDB('soar_db');

// Create collections
db.createCollection('alerts_raw');
db.createCollection('alerts_processed');
db.createCollection('actions_taken');
db.createCollection('model_predictions');
db.createCollection('feedback_data');
db.createCollection('system_config');
db.createCollection('api_keys');
db.createCollection('users');
db.createCollection('feedback_collection');
db.createCollection('action_priors_data');

print('✅ Collections created successfully');

// Create indexes for alerts_raw
db.alerts_raw.createIndex({ "timestamp": 1 });
db.alerts_raw.createIndex({ "siem_source": 1 });
db.alerts_raw.createIndex({ "alert_id": 1 }, { unique: true });
db.alerts_raw.createIndex(
  { "timestamp": 1 },
  { expireAfterSeconds: 7776000 }  // 90 days retention
);

print('✅ Indexes created for alerts_raw');

// Create indexes for alerts_processed
db.alerts_processed.createIndex({ "timestamp": 1, "severity": 1, "siem_source": 1 });
db.alerts_processed.createIndex({ "alert_id": 1 }, { unique: true });
db.alerts_processed.createIndex({ "correlation_group": 1 });
db.alerts_processed.createIndex({ "status": 1 });
db.alerts_processed.createIndex(
  { "description": "text", "classification": "text" }
);
db.alerts_processed.createIndex(
  { "timestamp": 1 },
  { expireAfterSeconds: 7776000 }  // 90 days retention
);

print('✅ Indexes created for alerts_processed');

// Create indexes for actions_taken
db.actions_taken.createIndex({ "alert_id": 1 });
db.actions_taken.createIndex({ "timestamp": 1 });
db.actions_taken.createIndex({ "action_type": 1 });
db.actions_taken.createIndex({ "status": 1 });
db.actions_taken.createIndex(
  { "timestamp": 1 },
  { expireAfterSeconds: 7776000 }  // 90 days retention
);

print('✅ Indexes created for actions_taken');

// Create indexes for model_predictions
db.model_predictions.createIndex({ "alert_id": 1 });
db.model_predictions.createIndex({ "timestamp": 1 });
db.model_predictions.createIndex({ "model_version": 1 });
db.model_predictions.createIndex(
  { "timestamp": 1 },
  { expireAfterSeconds: 7776000 }  // 90 days retention
);

print('✅ Indexes created for model_predictions');

// Create indexes for feedback_data
db.feedback_data.createIndex({ "alert_id": 1 });
db.feedback_data.createIndex({ "timestamp": 1 });
db.feedback_data.createIndex({ "analyst_id": 1 });
db.feedback_data.createIndex({ "feedback_type": 1 });

print('✅ Indexes created for feedback_data');

// Create indexes for users
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });

print('✅ Indexes created for users');

// Create indexes for api_keys
db.api_keys.createIndex({ "key_hash": 1 }, { unique: true });
db.api_keys.createIndex({ "siem_source": 1 });
db.api_keys.createIndex({ "is_active": 1 });

print('✅ Indexes created for api_keys');
// Create indexes for feedback_collection
db.feedback_collection.createIndex({ "incident_id": 1 }, { unique: true });
db.feedback_collection.createIndex({ "technique_id": 1 });
db.feedback_collection.createIndex({ "attack_stage": 1 });
db.feedback_collection.createIndex({ "decision": 1 });
db.feedback_collection.createIndex({ "false_positive": 1 });
db.feedback_collection.createIndex({ "original_plan": 1 });
db.feedback_collection.createIndex({ "analyst_plan": 1 });
db.feedback_collection.createIndex({ "removed_actions": 1 });
db.feedback_collection.createIndex({ "added_actions": 1 });
db.feedback_collection.createIndex({ "plan_rating": 1 });
db.feedback_collection.createIndex({ "analyst_metadata.analyst_id": 1 });
db.feedback_collection.createIndex({ "analyst_metadata.team": 1 });
db.feedback_collection.createIndex({ "analyst_metadata.confidence": 1 });
db.feedback_collection.createIndex({ "timestamps.feedback_submitted_at": 1 });
db.feedback_collection.createIndex({ "timestamps.incident_created_at": 1 });
db.feedback_collection.createIndex({ "execution_outcome.recurrence_within_7_days": 1 });
db.feedback_collection.createIndex({ "root_cause_analysis.dominant_cause.name": 1 });
db.feedback_collection.createIndex({ "root_cause_analysis.num_root_causes": 1 });
db.feedback_collection.createIndex(
  { "timestamps.feedback_submitted_at": 1 },
  { expireAfterSeconds: 31536000 }  // 1 year retention for audit trail
);

print('✅ Indexes created for feedback_collection');
print('��� MongoDB initialization completed successfully!');
