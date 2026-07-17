log_data = open("data/auth.log", "r")

failed_login_count = 0

for line in log_data:
    if "Failed password" in line:
        failed_login_count = failed_login_count + 1

print(failed_login_count)

log_data.close()