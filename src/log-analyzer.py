log_data = open("data/auth.log", "r")

failed_login_count = 0
failed_ips = []

for line in log_data:
    if "Failed password" in line:
        failed_login_count = failed_login_count + 1

        ip = line.split("from ")[1].split(" ")[0]
        failed_ips.append(ip)

print(f"Failed login attempts: {failed_login_count}")
print("Attacker IPs:")
print(failed_ips)

log_data.close()