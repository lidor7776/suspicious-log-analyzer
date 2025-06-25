import pandas as pd
from datetime import datetime, timedelta

# קריאת קובץ הלוגים
df = pd.read_csv("logs.csv")
df.columns = df.columns.str.strip()  # ניקוי שמות עמודות מרווחים/תווים נסתרים

# הצגת רשומות ראשונות
print("First log entries:")
print(df.head())

# המרת העמודה timestamp לפורמט תאריך-שעה
df['timestamp'] = pd.to_datetime(df['timestamp'])

# -----------------------------
# 🔍 זיהוי IP חשוד: 3 login_failed תוך פחות מ-5 דקות
# -----------------------------

# סינון פעולות של login_failed בלבד
failed_logins = df[df['action'] == 'login_failed']
suspicious_summary = []

# מעבר על כל IP ובדיקת רצפים חשודים (לפחות 2 ניסיונות בתוך 5 דקות)
for ip, group in failed_logins.groupby('ip'):
    times = group['timestamp'].sort_values().tolist()
    print(f"\n🔍 Checking IP: {ip}")
    print("Timestamps:", times)

    for i in range(len(times) - 1):
        diff = times[i + 1] - times[i]
        if diff <= timedelta(minutes=5):
            num_attempts = len(times)
            time_range = times[-1] - times[0] if num_attempts > 1 else timedelta(0)
            suspicious_summary.append({
                "ip": ip,
                "attempts": num_attempts,
                "time_range": time_range
            })
            print(f"   ✅ IP {ip} flagged: {num_attempts} failed logins in {time_range}")
            break


# -----------------------------
#  זיהוי פעולות בשעות לילה (00:00–05:00)
# -----------------------------

# חילוץ שעת הפעולה מכל timestamp
df['hour'] = df['timestamp'].dt.hour

# סינון רשומות לילה
night_logs = df[(df['hour'] >= 0) & (df['hour'] < 5)]

# הדפסה למסך
print("\nSuspicious log entries during unusual hours (00:00–05:00):")
print(night_logs[['timestamp', 'user', 'action', 'ip']].to_string(index=False))

# -----------------------------
# 📄 כתיבת דוח טקסט מסכם
# -----------------------------

with open("suspicious_report.txt", "w", encoding="utf-8") as report:
    report.write("Suspicious IPs (3+ failed logins in <5 min):\n")
    for entry in suspicious_summary:
        report.write(f"- {entry['ip']} | Attempts: {entry['attempts']} | Range: {entry['time_range']}\n")

    report.write("\nSuspicious log entries during unusual hours (00:00–05:00):\n")

    for _, row in night_logs.iterrows():
        timestamp = row['timestamp']
        user = row['user']
        action = row['action']
        ip = row['ip']
        report.write(f"{timestamp} | {user} | {action} | {ip}\n")

