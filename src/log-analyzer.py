log_data = open("data/auth.log", "r")

failed_login_count = 0
successful_login_count = 0

ip_counts = {}
user_counts = {}
successful_users = {}
ip_users = {}

for line in log_data:

    if "Failed password" in line:

        failed_login_count += 1

        ip = line.split("from ")[1].split(" ")[0]
        user = line.split("for ")[1].split("from ")[0].strip()

        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        user_counts[user] = user_counts.get(user, 0) + 1

        if ip not in ip_users:
            ip_users[ip] = {}

        ip_users[ip][user] = ip_users[ip].get(user, 0) + 1

    if "Accepted password" in line:

        successful_login_count += 1

        user = line.split("for ")[1].split("from ")[0].strip()

        successful_users[user] = successful_users.get(user, 0) + 1

print("Authentication Summary")
print("----------------------")
print(f"Failed login attempts: {failed_login_count}")
print(f"Successful logins: {successful_login_count}")

print()

sorted_ips = sorted(
    ip_counts.items(),
    key=lambda item: item[1],
    reverse=True
)

print("Top Attackers")
print("-------------")

for ip, count in sorted_ips:
    print(f"{ip} -> {count} attempts")

print()

sorted_users = sorted(
    user_counts.items(),
    key=lambda item: item[1],
    reverse=True
)

print("Top Target Accounts")
print("-------------------")

for user, count in sorted_users:
    print(f"{user} -> {count} attempts")

print()

print("Successful Users")
print("----------------")

for user, count in successful_users.items():
    print(f"{user} -> {count} successful logins")

print()

print("Attack Relationships")
print("--------------------")

for ip in ip_users:

    print(ip)

    for user, count in ip_users[ip].items():
        print(f"  {user} -> {count} attempts")

    print()

log_data.close()