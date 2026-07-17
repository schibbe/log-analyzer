log_data = open("data/auth.log", "r")

failed_login_count = 0
ip_counts = {}
user_counts = {}
ip_users = {}

for line in log_data:
    if "Failed password" in line:
        failed_login_count = failed_login_count + 1

        ip = line.split("from ")[1].split(" ")[0]
        user = line.split("for ")[1].split("from ")[0].strip()

        if ip in ip_counts:
            ip_counts[ip] = ip_counts[ip] + 1
        else:
            ip_counts[ip] = 1

        if user in user_counts:
            user_counts[user] = user_counts[user] + 1
        else:
            user_counts[user] = 1

        if ip not in ip_users:
            ip_users[ip] = {}

        if user in ip_users[ip]:
            ip_users[ip][user] = ip_users[ip][user] + 1
        else:
            ip_users[ip][user] = 1

print(f"Failed login attempts: {failed_login_count}")
print()

print("Attacker Statistics")
print("-------------------")

for ip in ip_counts:
    print(f"{ip} -> {ip_counts[ip]} attempts")

print()
print("Target Accounts")
print("----------------")

for user in user_counts:
    print(f"{user} -> {user_counts[user]} attempts")

print()
print("Attack Relationships")
print("--------------------")

for ip in ip_users:
    print(ip)

    for user in ip_users[ip]:
        print(f"  {user} -> {ip_users[ip][user]} attempts")

    print()

log_data.close()