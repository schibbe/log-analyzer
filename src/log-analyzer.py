log_data = open("data/auth.log", "r")

failed_login_count = 0
ip_counts = {}
user_counts = {}
ip_users = {}

for line in log_data:
    if "Failed password" in line:
        failed_login_count += 1

        ip = line.split("from ")[1].split(" ")[0]
        user = line.split("for ")[1].split("from ")[0].strip()

        if ip in ip_counts:
            ip_counts[ip] += 1
        else:
            ip_counts[ip] = 1

        if user in user_counts:
            user_counts[user] += 1
        else:
            user_counts[user] = 1

        if ip not in ip_users:
            ip_users[ip] = {}

        if user in ip_users[ip]:
            ip_users[ip][user] += 1
        else:
            ip_users[ip][user] = 1

print(f"Failed login attempts: {failed_login_count}")
print()

print("Attacker Statistics")
print("-------------------")

for ip, count in ip_counts.items():
    print(f"{ip} -> {count} attempts")

print()

print("Target Accounts")
print("----------------")

for user, count in user_counts.items():
    print(f"{user} -> {count} attempts")

print()

print("Attack Relationships")
print("--------------------")

for ip in ip_users:
    print(ip)

    for user, count in ip_users[ip].items():
        print(f"  {user} -> {count} attempts")

    print()

log_data.close()