import json
from datetime import datetime
from collections import Counter, defaultdict

print("Loading alerts...")
with open('synthetic_wazuh_alerts.json', 'r') as f:
    alerts = json.load(f)

print(f"\n{'='*70}")
print("WEEKDAY VS WEEKEND ALERT ANALYSIS")
print(f"{'='*70}")

# Parse timestamps and categorize by weekday/weekend
weekday_alerts = []
weekend_alerts = []
day_distribution = Counter()
hour_distribution_weekday = Counter()
hour_distribution_weekend = Counter()

for alert in alerts:
    timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
    day_name = timestamp.strftime('%A')
    day_of_week = timestamp.weekday()  # 0=Monday, 6=Sunday
    hour = timestamp.hour
    
    day_distribution[day_name] += 1
    
    if day_of_week >= 5:  # Saturday=5, Sunday=6
        weekend_alerts.append(alert)
        hour_distribution_weekend[hour] += 1
    else:
        weekday_alerts.append(alert)
        hour_distribution_weekday[hour] += 1

# Calculate statistics
total_alerts = len(alerts)
weekday_count = len(weekday_alerts)
weekend_count = len(weekend_alerts)

# Count actual weekdays and weekends in the 90-day period
start_date = datetime.fromisoformat(alerts[0]['timestamp'].replace('Z', '+00:00'))
end_date = datetime.fromisoformat(alerts[-1]['timestamp'].replace('Z', '+00:00'))
date_range = (end_date - start_date).days + 1

weekdays_in_range = 0
weekends_in_range = 0
current_date = start_date.date()
end = end_date.date()

while current_date <= end:
    if current_date.weekday() >= 5:
        weekends_in_range += 1
    else:
        weekdays_in_range += 1
    from datetime import timedelta
    current_date += timedelta(days=1)

# Average per day
avg_per_weekday = weekday_count / weekdays_in_range if weekdays_in_range > 0 else 0
avg_per_weekend = weekend_count / weekends_in_range if weekends_in_range > 0 else 0

print(f"\n📊 Overall Distribution:")
print(f"  Total Alerts: {total_alerts:,}")
print(f"  Data Range: {date_range} days")
print(f"  Weekdays in range: {weekdays_in_range} days")
print(f"  Weekend days in range: {weekends_in_range} days")

print(f"\n⏰ Weekday vs Weekend:")
print(f"  Weekday alerts (Mon-Fri): {weekday_count:,} ({weekday_count/total_alerts*100:.1f}%)")
print(f"  Weekend alerts (Sat-Sun): {weekend_count:,} ({weekend_count/total_alerts*100:.1f}%)")

print(f"\n📈 Average Alerts Per Day:")
print(f"  Average per weekday: {avg_per_weekday:.1f} alerts/day")
print(f"  Average per weekend day: {avg_per_weekend:.1f} alerts/day")
print(f"  Ratio (weekday/weekend): {avg_per_weekday/avg_per_weekend:.2f}x" if avg_per_weekend > 0 else "N/A")

print(f"\n📅 Distribution by Day of Week:")
day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
for day in day_order:
    count = day_distribution[day]
    percentage = (count / total_alerts) * 100
    bar = '█' * int(percentage * 2)
    print(f"  {day:10s}: {count:5,} ({percentage:5.2f}%) {bar}")

print(f"\n🕐 Peak Hours - Weekdays:")
top_weekday_hours = hour_distribution_weekday.most_common(5)
for hour, count in top_weekday_hours:
    percentage = (count / weekday_count) * 100
    print(f"  {hour:02d}:00: {count:4,} alerts ({percentage:5.2f}%)")

print(f"\n🕐 Peak Hours - Weekends:")
top_weekend_hours = hour_distribution_weekend.most_common(5)
for hour, count in top_weekend_hours:
    percentage = (count / weekend_count) * 100 if weekend_count > 0 else 0
    print(f"  {hour:02d}:00: {count:4,} alerts ({percentage:5.2f}%)")

print(f"\n{'='*70}")
