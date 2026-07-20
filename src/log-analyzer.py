def print_sorted_dictionary(data, title, label):

    sorted_data = sorted(
        data.items(),
        key=lambda item: item[1],
        reverse=True
    )

    print(title)
    print("-" * len(title))

    for key, count in sorted_data:
        print(f"{key} -> {count} {label}")

    print()


def print_attack_relationships(ip_users):

    print("Attack Relationships")
    print("--------------------")

    for ip in ip_users:

        print(ip)

        for user, count in ip_users[ip].items():
            print(f"  {user} -> {count} attempts")

        print()


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

print_sorted_dictionary(
    ip_counts,
    "Top Attackers",
    "attempts"
)

print_sorted_dictionary(
    user_counts,
    "Top Target Accounts",
    "attempts"
)

print_sorted_dictionary(
    successful_users,
    "Successful Users",
    "successful logins"
)

print_attack_relationships(ip_users)

log_data.close()