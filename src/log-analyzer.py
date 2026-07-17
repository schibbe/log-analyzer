log_data = open("data/auth.log", "r")

for line in log_data:
    if "Failed password" in line:
        print(line)

log_data.close()