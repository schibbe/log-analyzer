def print_section_header(title):

    print(title)
    print("-" * len(title))


def print_sorted_dictionary(data, title, label):

    sorted_data = sorted(
        data.items(),
        key=lambda item: item[1],
        reverse=True
    )

    print_section_header(title)

    for key, count in sorted_data:
        print(f"{key} -> {count} {label}")

    print()


def print_attack_relationships(ip_users):

    print_section_header("Attack Relationships")

    for ip in ip_users:

        print(ip)

        for user, count in ip_users[ip].items():
            print(f"  {user} -> {count} attempts")

        print()


def print_password_spraying_attacks(ip_users):

    print_section_header("Potential Password Spraying Attacks")

    for ip, users in ip_users.items():

        attacked_users = len(users)

        if attacked_users >= PASSWORD_SPRAY_THRESHOLD:
            print(
                f"{ip} -> "
                f"{attacked_users} different user accounts targeted"
            )

    print()



def print_high_value_accounts(user_counts):

    print_section_header("High-Value Account Targets")

    for user, count in user_counts.items():

        if user in HIGH_VALUE_ACCOUNTS:
            print(f"{user} -> {count} failed login attempts")

    print()


def print_invalid_users(invalid_users):

    print_sorted_dictionary(
        invalid_users,
        "Invalid User Attacks",
        "attempts"
    )



def print_successful_logins_after_failed_attempts(compromised_logins):

    print_section_header("Successful Logins After Failed Attempts")

    for ip, user in compromised_logins:
        print(f"{ip} -> {user}")

    print()

def print_authentication_summary(failed_login_count, successful_login_count):

    print_section_header("Authentication Summary")

    print(f"Failed login attempts: {failed_login_count}")
    print(f"Successful logins: {successful_login_count}")
    print()


def get_severity(count):

    if count >= CRITICAL_THRESHOLD:
        return "CRITICAL"

    elif count >= HIGH_THRESHOLD:
        return "HIGH"

    elif count >= MEDIUM_THRESHOLD:
        return "MEDIUM"

    elif count >= LOW_THRESHOLD:
        return "LOW"

    return None


def parse_log_entry(line):

    timestamp = line[:15]
    hour = timestamp.split()[2].split(":")[0]
    ip = line.split("from ")[1].split(" ")[0]
    user = line.split("for ")[1].split("from ")[0].strip()

    return timestamp, hour, user, ip


BRUTE_FORCE_THRESHOLD = 10
PASSWORD_SPRAY_THRESHOLD = 5

LOW_THRESHOLD = 10
MEDIUM_THRESHOLD = 25
HIGH_THRESHOLD = 50
CRITICAL_THRESHOLD = 100

HIGH_VALUE_ACCOUNTS = [
    "root",
    "admin",
    "oracle",
    "postgres",
    "mysql"
]

failed_login_count = 0
successful_login_count = 0

ip_counts = {}
user_counts = {}
successful_users = {}
successful_ips = {}
ip_users = {}
hourly_attacks = {}
invalid_users = {}
failed_ips = {}
compromised_logins = []

with open("data/auth.log", "r") as log_data:

    for line in log_data:

        timestamp, hour, user, ip = parse_log_entry(line)

        if "Failed password" in line:

            failed_login_count += 1

            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            user_counts[user] = user_counts.get(user, 0) + 1
            hourly_attacks[hour] = hourly_attacks.get(hour, 0) + 1

            if ip not in ip_users:
                ip_users[ip] = {}

            ip_users[ip][user] = ip_users[ip].get(user, 0) + 1
            failed_ips[ip] = user

        if "Invalid user" in line:

            invalid_user = line.split("Invalid user ")[1].split(" ")[0]

            invalid_users[invalid_user] = (
                invalid_users.get(invalid_user, 0) + 1
            )

        if "Accepted password" in line:

            successful_login_count += 1

            successful_users[user] = successful_users.get(user, 0) + 1
            successful_ips[ip] = successful_ips.get(ip, 0) + 1

            if ip in failed_ips:
                compromised_logins.append((ip, user))

print_authentication_summary(
    failed_login_count,
    successful_login_count
)

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

print_section_header("Potential Brute-Force Attacks")

for ip, count in ip_counts.items():

    severity = get_severity(count)

    if severity is None:
        continue

    print(f"[{severity}] {ip} -> {count} failed login attempts")

print()

print_password_spraying_attacks(ip_users)

print_high_value_accounts(user_counts)

print_successful_logins_after_failed_attempts(compromised_logins)

print_invalid_users(invalid_users)

print_section_header("Successful Brute-Force Candidates")

for ip in successful_ips:

    if ip in ip_counts and ip_counts[ip] >= BRUTE_FORCE_THRESHOLD:
        print(
            f"{ip} -> "
            f"{ip_counts[ip]} failed attempts, "
            f"{successful_ips[ip]} successful login(s)"
        )

print()

print_section_header("Attack Activity by Hour")

sorted_hours = sorted(hourly_attacks.items())

for hour, count in sorted_hours:
    print(f"{hour}:00 -> {count} failed login attempts")
